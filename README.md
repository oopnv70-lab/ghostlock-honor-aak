# ghostlock-honor-aak

GhostLock (CVE-2026-43499) exploit adapted for Honor AAK-AN00 (MagicOS 10, kernel 6.6.89-android15)

---

## ⚠️ LEGAL NOTICE / 法律声明 / RECHTLICHER HINWEIS / AVIS JURIDIQUE / 法的通知 / NOTA LEGAL / ข้อกฎหมาย / ЮРИДИЧЕСКОЕ УВЕДОМЛЕНИЕ / إشعار قانوني

### English

This software is provided solely for **authorized security research, academic study, and penetration testing on devices you own or have explicit written permission to test.** Any unauthorized use of this software to access computer systems without consent is illegal and may violate:

- **PRC Criminal Law Article 285** (Illegal intrusion into computer information systems)
- **18 U.S.C. § 1030** (Computer Fraud and Abuse Act, United States)
- **Computer Misuse Act 1990** (United Kingdom)
- **Directive 2013/40/EU** (European Union — attacks against information systems)
- Similar cybercrime laws in your jurisdiction

**The author(s) assume NO LIABILITY for any misuse, damage, or legal consequences arising from the use of this software. By using, downloading, or distributing this code, you acknowledge that you assume all responsibility for your actions.**

---

### 简体中文

本软件**仅限**用于以下合法场景：
- 拥有明确书面授权的安全测试
- 学术研究与漏洞验证
- 对**本人合法拥有的设备**进行渗透测试

**严禁**将本软件用于任何未经授权的计算机系统入侵。非法使用可能触犯：

- **《中华人民共和国刑法》第二百八十五条**（非法侵入计算机信息系统罪）
- **《中华人民共和国网络安全法》**
- **《中华人民共和国数据安全法》**

**作者不承担因滥用本软件而产生的任何法律责任、损害赔偿或法律后果。下载、使用或分发本代码即表示你自行承担全部行为责任。**

---

### 繁體中文

本軟體**僅限**用於以下合法場景：
- 擁有明確書面授權的安全測試
- 學術研究與漏洞驗證
- 對**本人合法擁有的裝置**進行滲透測試

**嚴禁**將本軟體用於任何未經授權的電腦系統入侵。非法使用可能觸犯《中華民國刑法》第三十六章妨害電腦使用罪（第358-363條）、**香港《刑事罪行條例》第161條**（有犯罪或不誠實意圖而取用電腦）及其他司法管轄區之相關法律。

**作者不承擔因濫用本軟體而產生之任何法律責任、損害賠償或法律後果。**

---

### Deutsch (German)

Diese Software dient **ausschließlich** autorisierten Sicherheitsforschung, akademischen Studien und Penetrationstests an Geräten, die Sie besitzen oder für die Sie eine ausdrückliche schriftliche Genehmigung haben. Jegliche unbefugte Nutzung kann gegen § 202a StGB (Ausspähen von Daten), § 303b StGB (Computersabotage) und andere anwendbare Gesetze verstoßen.

**Der/die Autor(en) übernehmen KEINE HAFTUNG für Missbrauch, Schäden oder rechtliche Konsequenzen.**

---

### Français (French)

Ce logiciel est fourni **uniquement** à des fins de recherche en sécurité autorisée, d'études académiques et de tests d'intrusion sur des appareils que vous possédez ou pour lesquels vous disposez d'une autorisation écrite explicite. Toute utilisation non autorisée peut violer les articles 323-1 à 323-7 du Code pénal français et d'autres lois applicables.

**L'auteur/les auteurs déclinent TOUTE RESPONSABILITÉ en cas d'utilisation abusive, de dommages ou de conséquences juridiques.**

---

### 日本語 (Japanese)

本ソフトウェアは、**明示的な書面による許可を得たセキュリティ研究、学術調査、およびご自身が所有するデバイスに対するペネトレーションテスト**にのみ使用できます。不正アクセス行為の禁止等に関する法律（不正アクセス禁止法）その他の関連法令に違反する使用は固く禁じられています。

**作者は、本ソフトウェアの誤用によって生じたいかなる損害、法的結果についても一切の責任を負いません。**

---

### Español (Spanish)

Este software se proporciona **únicamente** para investigación de seguridad autorizada, estudios académicos y pruebas de penetración en dispositivos de su propiedad o para los que tenga permiso explícito por escrito. El uso no autorizado puede violar el Código Penal aplicable en su jurisdicción.

**El/los autor(es) NO ASUMEN RESPONSABILIDAD alguna por el uso indebido, daños o consecuencias legales.**

---

### Русский (Russian)

Данное программное обеспечение предназначено **исключительно** для авторизованных исследований в области безопасности, академических исследований и тестирования на проникновение на устройствах, которыми вы владеете или на тестирование которых имеете явное письменное разрешение. Несанкционированное использование может нарушать ст. 272 УК РФ (Неправомерный доступ к компьютерной информации) и другие применимые законы.

**Автор(ы) НЕ НЕСУТ ОТВЕТСТВЕННОСТИ за неправомерное использование, ущерб или правовые последствия.**

---

### العربية (Arabic)

هذا البرنامج مقدم **حصريًا** لأغراض البحث الأمني المصرح به والدراسات الأكاديمية واختبار الاختراق على الأجهزة التي تمتلكها أو لديك إذن كتابي صريح باختبارها. الاستخدام غير المصرح به قد ينتهك القوانين المعمول بها في نطاق سلطتك القضائية.

**المؤلف(ون) لا يتحملون أي مسؤولية عن سوء الاستخدام أو الأضرار أو العواقب القانونية.**

---

### 한국어 (Korean)

본 소프트웨어는 **명시적인 서면 허가를 받은 보안 연구, 학술 연구 및 본인이 소유한 장치에 대한 침투 테스트** 목적으로만 제공됩니다. 무단 사용은 「정보통신망 이용촉진 및 정보보호 등에 관한 법률」 및 기타 관련 법률을 위반할 수 있습니다.

**작성자는 본 소프트웨어의 오용, 손해 또는 법적 결과에 대해 어떠한 책임도 지지 않습니다.**

---

### GPL-3.0 License

This project is licensed under the GNU General Public License v3.0.
See [LICENSE](LICENSE) for full text.

---

## Build Status

CI: GitHub Actions (NDK r29, ARM64 static)

## Target

| Item | Value |
|------|-------|
| Device | Honor AAK-AN00 |
| OS | MagicOS 10 |
| Kernel | 6.6.89-android15 |
| Arch | aarch64 |
| CVE | CVE-2026-43499 (GhostLock) |
