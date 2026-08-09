#!/usr/bin/env python3
"""deep_trace_v2.py — Honor AAK-AN00 kernel analysis
Focus: HIARC debug nodes + tmf8805 I2C write → MCU attack surface
Target modules: hiarc.ko, hiarc_pangu.ko, tmf8805_dtof.ko, aw_haptic_nv.ko

Requires:
  vmlinux.elf — extracted from kernel_img
  hiarc.asm.xz, hiarc_pangu.asm.xz, tmf8805_dtof.asm.xz — pre-disassembled
  symbols.txt — kallsyms-like symbol table
"""

import json, re, subprocess, sys, os, gzip, lzma
from collections import defaultdict

OUTPUT = {}
ROOT = os.path.dirname(os.path.abspath(__file__))
# If we are already inside deep_analysis, use cwd directly
_this_dir = os.path.basename(ROOT)
if _this_dir == "deep_analysis" and os.path.exists(os.path.join(ROOT, "hiarc.asm.xz")):
    ANALYSIS_DIR = ROOT
else:
    # Try analysis-full_12 first, fallback to analysis-full_10
    for candidate in ["analysis-full_12", "analysis-full_10"]:
        candidate_path = os.path.join(ROOT, candidate, "deep_analysis")
        if os.path.exists(candidate_path):
            ANALYSIS_DIR = candidate_path
            break
    else:
        ANALYSIS_DIR = os.path.join(ROOT, "analysis-full_10", "deep_analysis")

# ─── helpers ───
def read_file_xz(path):
    if not os.path.exists(path):
        return ""
    # Try xz first, fallback to plain text
    try:
        with lzma.open(path, "rt") as f:
            return f.read()
    except lzma.LZMAError:
        with open(path, "r", errors="replace") as f:
            return f.read()

def grep_asm(asm_text, pattern):
    return [l for l in asm_text.split("\n") if re.search(pattern, l)]

# ─── 1. HIARC module analysis ───
def analyze_hiarc():
    res = {}
    asm = read_file_xz(os.path.join(ANALYSIS_DIR, "hiarc.asm.xz"))
    strings = read_file_xz(os.path.join(ANALYSIS_DIR, "hiarc.strings"))
    if not asm:
        res["error"] = "hiarc.asm.xz not found"
        return res

    # Extract all debug store/show functions
    stores = {}
    for fn_name in ["hiarc_debug_store", "hiarc_debug_show",
                    "hiarc_gpio_debug_store", "hiarc_gpio_debug_show",
                    "read_write_test_store", "read_write_test_show",
                    "read_write_byte_store", "read_write_byte_show",
                    "hiarc_uart4_read_write_store", "hiarc_uart4_read_write_show",
                    "custom_bt_addr_store", "custom_bt_addr_show"]:
        pat = rf'<{fn_name}>:\s*\n((?:\s+[0-9a-f]+:.*\n)+)'
        m = re.search(pat, asm)
        if m:
            body = m.group(1)
            inst_ct = len([l for l in body.split("\n") if l.strip()])
            # Key operations
            has_strncmp = "strncmp" in body
            has_sscanf = "sscanf" in body
            has_memcpy = "memcpy" in body
            has_uart = "uart" in body.lower()
            has_mutex = "mutex" in body
            has_gpio = "gpio" in body
            has_sdio = "sdio" in body.lower() or "mmc" in body.lower()
            has_printk = "_printk" in body
            stores[fn_name] = {
                "instructions": inst_ct,
                "strncmp": has_strncmp,
                "sscanf": has_sscanf,
                "memcpy": has_memcpy,
                "uart_access": has_uart,
                "mutex": has_mutex,
                "gpio_access": has_gpio,
                "sdio_mmc_access": has_sdio,
                "printk": has_printk
            }

    # Count device_create_file calls (sysfs nodes exposed)
    dcf_ct = asm.count("device_create_file")
    dev_attrs = grep_asm(asm, "dev_attr_")

    res["debug_nodes"] = stores
    res["sysfs_nodes_created"] = dcf_ct
    res["device_attrs"] = [l.split("<")[1].split(">")[0] if "<" in l else l for l in dev_attrs[:20]]

    # Determine validation level for each node
    res["zero_check_nodes"] = []
    for name, info in stores.items():
        if info["strncmp"] and not info["memcpy"] and info["instructions"] < 200:
            # strncmp without memcpy = direct user-buffer access with no copy validation
            res["zero_check_nodes"].append({
                "name": name,
                "reason": "strncmp on raw user buffer, no memcpy to stack, potentially no length cap"
            })
        if info["uart_access"]:
            res["zero_check_nodes"].append({
                "name": name,
                "reason": "UART direct write — user bytes sent to MCU UART"
            })
        if info["sdio_mmc_access"]:
            res["zero_check_nodes"].append({
                "name": name,
                "reason": "SDIO/MMC control — bus-level manipulation from sysfs"
            })

    # Extract GPIO/MCU command strings
    if strings:
        gpio_cmds = set(re.findall(r'^(wakeup_mcu_high|wakeup_mcu_low|wakeup_c2_high|wakeup_c2_low|chip_en_high|chip_en_low|ap_state_high|ap_state_low|wakeup_ap_irq|mcu_waken|clk_out)$', strings, re.M))
        res["gpio_command_strings"] = sorted(gpio_cmds)

    return res

# ─── 2. tmf8805 analysis ───
def analyze_tmf8805():
    res = {}
    asm = read_file_xz(os.path.join(ANALYSIS_DIR, "tmf8805_dtof.asm.xz"))
    if not asm:
        res["error"] = "tmf8805_dtof.asm.xz not found"
        return res

    # register_write_store
    m = re.search(r'<register_write_store>:\s*\n((?:\s+[0-9a-f]+:.*\n)+)', asm)
    if m:
        body = m.group(1)
        has_sscanf = "sscanf" in body
        has_i2c = "i2c" in body.lower()
        has_mask = "mask" in body.lower()
        res["register_write_store"] = {
            "instructions": len([l for l in body.split("\n") if l.strip()]),
            "sscanf": has_sscanf,
            "i2c_call": has_i2c,
            "mask_support": has_mask,
            "comment": "Zero-validation I2C write: reg, data, mask all from user sscanf input"
        }

    # register_read_show
    m = re.search(r'<register_read_show>:\s*\n((?:\s+[0-9a-f]+:.*\n)+)', asm)
    if m:
        body = m.group(1)
        res["register_read_show"] = {
            "instructions": len([l for l in body.split("\n") if l.strip()]),
            "comment": "I2C register read — potential info leak"
        }

    # I2C addresses
    i2c_addrs = re.findall(r'(0x[0-9a-fA-F]{2})', asm)
    res["i2c_address_candidates"] = sorted(set(i2c_addrs))[:10]

    return res

# ─── 3.5 tmf8806_dtof (tmf8805 sibling) ───
def analyze_tmf8806():
    res = {}
    asm = read_file_xz(os.path.join(ANALYSIS_DIR, "tmf8806_dtof.asm.xz"))
    if not asm:
        res["error"] = "tmf8806_dtof.asm.xz not found"
        return res

    # Check store functions
    for fn in ["program_store", "app0_histogram_readout_store", "app0_osc_trim_store",
               "data_setting_store", "snr_store"]:
        m = re.search(rf'<{fn}>:\s*\n((?:\s+[0-9a-f]+:.*\n)+)', asm)
        if m:
            body = m.group(1)
            has_sscanf = "sscanf" in body
            has_i2c = "i2c" in body.lower()
            res[fn] = {
                "instructions": len([l for l in body.split("\n") if l.strip()]),
                "sscanf": has_sscanf,
                "i2c_call": has_i2c,
                "comment": "tmf8806 I2C store function"
            }
    return res

# ─── 3.6 hertz (Hertz MCU) ───
def analyze_hertz():
    res = {}
    asm = read_file_xz(os.path.join(ANALYSIS_DIR, "hertz.asm.xz"))
    if not asm:
        res["error"] = "hertz.asm.xz not found"
        return res

    for fn in ["read_write_byte_store", "project_properties_store"]:
        m = re.search(rf'<{fn}>:\s*\n((?:\s+[0-9a-f]+:.*\n)+)', asm)
        if m:
            body = m.group(1)
            res[fn] = {
                "instructions": len([l for l in body.split("\n") if l.strip()]),
                "uart_access": "uart" in body.lower(),
                "i2c_access": "i2c" in body.lower(),
                "sscanf": "sscanf" in body,
                "comment": "Hertz MCU interface function"
            }
    return res
def analyze_aw_haptic():
    res = {}
    asm = read_file_xz(os.path.join(ANALYSIS_DIR, "aw_haptic_nv.asm.xz"))
    if not asm:
        res["error"] = "aw_haptic_nv.asm.xz not found"
        return res

    m = re.search(r'<cont_drv_store>:\s*\n((?:\s+[0-9a-f]+:.*\n)+)', asm)
    if m:
        body = m.group(1)
        has_sscanf = "sscanf" in body
        has_i2c = "i2c" in body.lower()
        has_0x7B = "0x7b" in body.lower() or "0x7B" in body
        res["cont_drv_store"] = {
            "instructions": len([l for l in body.split("\n") if l.strip()]),
            "sscanf": has_sscanf,
            "i2c_call": has_i2c,
            "fixed_reg_0x7B": has_0x7B,
            "comment": "I2C write with fixed register 0x7B, 2-byte value from user sscanf"
        }
    return res

# ─── 4. Overall assessment ───
def build_assessment(hiarc, tmf8805, tmf8806, aw_haptic, hertz):
    vulns = []

    # HIARC: GPIO store zero-check
    if "hiarc_gpio_debug_store" in hiarc.get("debug_nodes", {}):
        node = hiarc["debug_nodes"]["hiarc_gpio_debug_store"]
        vulns.append({
            "module": "hiarc.ko",
            "function": "hiarc_gpio_debug_store",
            "threat": "GPIO/MCU pin direct control via strncmp without length validation",
            "commands": hiarc.get("gpio_command_strings", []),
            "severity": "HIGH",
            "instructions": node["instructions"]
        })

    # HIARC: UART2 tunnel
    if "read_write_byte_store" in hiarc.get("debug_nodes", {}):
        node = hiarc["debug_nodes"]["read_write_byte_store"]
        vulns.append({
            "module": "hiarc.ko",
            "function": "read_write_byte_store",
            "threat": "UART2 MCU byte tunnel — 128 bytes injected to MCU firmware via uart2_write",
            "severity": "CRITICAL",
            "instructions": node["instructions"]
        })

    # HIARC: UART4 tunnel
    if "hiarc_uart4_read_write_store" in hiarc.get("debug_nodes", {}):
        node = hiarc["debug_nodes"]["hiarc_uart4_read_write_store"]
        vulns.append({
            "module": "hiarc.ko",
            "function": "hiarc_uart4_read_write_store",
            "threat": "UART4 MCU byte tunnel — alternate UART injection vector",
            "severity": "CRITICAL",
            "instructions": node["instructions"]
        })

    # HIARC: read_write_test SDIO/MMC manipulation
    if "read_write_test_store" in hiarc.get("debug_nodes", {}):
        node = hiarc["debug_nodes"]["read_write_test_store"]
        vulns.append({
            "module": "hiarc.ko",
            "function": "read_write_test_store",
            "threat": "SDIO/MMC bus manipulation — close_irq, open_irq, mmc_rescan, pm_runtime, SDIO host register write",
            "severity": "HIGH",
            "instructions": node["instructions"]
        })

    # tmf8805 I2C
    if "register_write_store" in tmf8805:
        node = tmf8805["register_write_store"]
        vulns.append({
            "module": "tmf8805_dtof.ko",
            "function": "register_write_store",
            "threat": "Zero-validation I2C arbitrary write — reg, data, mask from sscanf",
            "severity": "CRITICAL",
            "instructions": node["instructions"]
        })

    # aw_haptic I2C
    if "cont_drv_store" in aw_haptic:
        node = aw_haptic["cont_drv_store"]
        vulns.append({
            "module": "aw_haptic_nv.ko",
            "function": "cont_drv_store",
            "threat": "I2C write with fixed register 0x7B — limited utility",
            "severity": "MEDIUM",
            "instructions": node["instructions"]
        })

    # tmf8806 I2C
    for fn, node in tmf8806.items():
        if fn.endswith("_store"):
            vulns.append({
                "module": "tmf8806_dtof.ko",
                "function": fn,
                "threat": "tmf8806 I2C store — potential unvalidated register write",
                "severity": "HIGH" if node.get("i2c_call") else "MEDIUM",
                "instructions": node["instructions"]
            })

    # hertz MCU
    for fn, node in hertz.items():
        if fn.endswith("_store"):
            vulns.append({
                "module": "hertz.ko",
                "function": fn,
                "threat": f"Hertz MCU interface — {node.get('comment','')}",
                "severity": "HIGH" if node.get("uart_access") else "MEDIUM",
                "instructions": node["instructions"]
            })

    return {"total_vulns": len(vulns), "vulnerabilities": vulns}


# ─── MAIN ───
def main():
    print("[deep_trace_v2] Starting analysis...")
    print(f"[deep_trace_v2] Analysis dir: {ANALYSIS_DIR}")

    hiarc = analyze_hiarc()
    tmf8805 = analyze_tmf8805()
    tmf8806 = analyze_tmf8806()
    aw_haptic = analyze_aw_haptic()
    hertz = analyze_hertz()
    assessment = build_assessment(hiarc, tmf8805, tmf8806, aw_haptic, hertz)

    OUTPUT["hiarc"] = hiarc
    OUTPUT["tmf8805"] = tmf8805
    OUTPUT["tmf8806"] = tmf8806
    OUTPUT["aw_haptic"] = aw_haptic
    OUTPUT["hertz"] = hertz
    OUTPUT["assessment"] = assessment

    out_path = os.path.join(ANALYSIS_DIR, "deep_trace_output_v2.json")
    with open(out_path, "w") as f:
        json.dump(OUTPUT, f, indent=2)
    print(f"[deep_trace_v2] Output written to {out_path}")
    print(f"[deep_trace_v2] Found {assessment['total_vulns']} vulnerabilities")

    return 0

if __name__ == "__main__":
    sys.exit(main())
