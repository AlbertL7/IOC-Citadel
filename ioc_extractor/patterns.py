"""
patterns.py - Compiled regex patterns for IOC extraction.

Contains all the regular expressions used to identify Indicators of Compromise
(IOCs) in text input. Patterns support both standard and defanged formats.

Supported IOC types:
  - IPv4 / IPv6 addresses (including defanged with [.] and (.))
  - IPv4 with port (IP:port)
  - CIDR notation (IP/prefix)
  - Domains and subdomains (including [dot] defanged)
  - URLs (including defanged hxxp, [.] notation)
  - File hashes (MD5, SHA1, SHA256, SHA512, SSDEEP)
  - JARM / JA3 / JA3S / JA4+ fingerprints
  - IMPHASH (PE import hash)
  - CVE identifiers
  - MITRE ATT&CK technique/tactic IDs
  - Threat group IDs (APT, FIN, UNC, DEV, TA)
  - STIX 2.x object IDs
  - Snort/Suricata signature IDs
  - File names (inside and outside quotes)
  - Email addresses (including defanged)
  - Windows registry keys (HKLM, HKCU, HKCR, HKU, HKEY_*)
  - Windows file paths (C:\\..., D:\\...)
  - UNC paths (\\\\server\\share)
  - PDB debug paths
  - Named pipes (\\\\.\\pipe\\...)
  - MAC addresses
  - Cryptocurrency addresses (Bitcoin, Ethereum, Monero + integrated)
  - Dark web (.onion) addresses
  - ASN numbers
  - YARA rules (full rule blocks)
  - Sigma rules (YAML detection blocks)
  - Sigma rule IDs (UUID references)
  - Snort/Suricata rules (full alert/drop rules with sid)
  - ModSecurity/WAF rules (SecRule directives)
  - Mutex / Mutant names
  - User-Agent strings
  - Scheduled task commands (schtasks)
  - Windows service commands (sc create/config)
  - PowerShell encoded commands
  - Google Analytics / Adsense IDs
  - AWS S3 bucket references
  - Abuse.ch references (URLhaus, MalBazaar, ThreatFox)
"""

import re

# ---------------------------------------------------------------------------
# Helper constants used to build regex patterns
# ---------------------------------------------------------------------------

SEPARATOR_DEFANGS = r"[\(\)\[\]{}<>\\]"
END_PUNCTUATION = r"[\.\?>\"'\)!,}:;\u201d\u2019\uff1e\uff1c\]]*"

# IPv4 pattern string (also used inside IPv6)
IPV4_PATTERN_STR = (
    r"\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

# IPv6 segment
_V6SEG = r"[a-fA-F\b]{1,4}"
IPV6_PATTERN_STR = (
    "("
    f"(?:{_V6SEG}:){{7}}{_V6SEG}|"
    f"(?:{_V6SEG}:){{7}}(?::{_V6SEG}|:)|"
    f"(?:{_V6SEG}:){{6}}(?::{IPV4_PATTERN_STR}|(?::{_V6SEG}){{1,2}}|:)|"
    f"(?:{_V6SEG}:){{5}}(?::{IPV4_PATTERN_STR}|(?::{_V6SEG}){{1,2}}|:)|"
    f"(?:{_V6SEG}:){{4}}(?:(?::{_V6SEG})?:{IPV4_PATTERN_STR}|(?::{_V6SEG}){{1,3}}|:)|"
    f"(?:{_V6SEG}:){{3}}(?:(?::{_V6SEG}){{0,2}}:{IPV4_PATTERN_STR}|(?::{_V6SEG}){{1,4}}|:)|"
    f"(?:{_V6SEG}:){{2}}(?:(?::{_V6SEG}){{0,3}}:{IPV4_PATTERN_STR}|(?::{_V6SEG}){{1,5}}|:)|"
    f"(?:{_V6SEG}:){{1}}(?:(?::{_V6SEG}){{0,4}}:{IPV4_PATTERN_STR}|(?::{_V6SEG}){{1,6}}|:)|"
    f"(?::((?::{_V6SEG}){{0,5}}:{IPV4_PATTERN_STR}|(?::{_V6SEG}){{1,7}}|:))"
    ")(?:%[0-9a-zA-Z]{1,})?"
)

# Exhaustive file extension list
FILE_EXTENSIONS = (
    r"(doc|hta|docx|pdf|au3|ppt|bin|old|pptx|mui|txt|rtf|xls|diff|xlsx|odt|"
    r"jpeg|jpg|png|me|info|biz|gif|bmp|svg|tiff|psd|ico|mp3|wav|aac|flac|ogg|"
    r"m4a|wma|mp4|avi|mkv|flv|mov|wmv|mpeg|zip|rar|7z|tar|gz|bz2|iso|html|htm|"
    r"css|js|php|py|java|cpp|c|h|cs|sql|db|mdb|xml|json|exe|dll|sys|ini|bat|vbs|"
    r"dwg|dxf|3ds|max|skp|proj|aep|prproj|veg|cad|stl|step|dat|csv|log|mat|nc|"
    r"vmdk|vdi|img|qcow2|ttf|otf|fon|bak|tmp|dmp|epub|mobi|azw|azw3|git|svn|sh|"
    r"bash|ps1|cmd|cfg|conf|yml|yaml|sass|scss|less|jsx|ts|tsx|npm|gem|pip|jar|"
    r"deb|rpm|swf|lisp|go|rb|r|vmx|ova|ovf|vhdx|hdd|mid|midi|als|ftm|rex|unity|"
    r"blend|unr|pak|bsp|pem|crt|csr|key|pgp|apk|ipa|app|aab|xapk|md|markdown|"
    r"tex|bib|cls|vrml|x3d|u3d|ar|sbsar|ovpn|pcf|cisco|rdp|ssh|spss|sav|rdata|"
    r"dta|do|ftl|twig|jinja|tpl|edml|obj|mtl|dae|abc|c4d|fbx|vrm|glb|gltf|usdz|"
    r"reg|pol|inf|msi|msp|awk|sed|groovy|lua|tcl|gitignore|gitattributes|"
    r"hgignore|dockerfile|dockerignore|sqlite|dbf|accdb|ora|frm|chm|mht|epub|"
    r"mobi|lit|ai|eps|indd|xd|fig|rbw|pl|swift|kt|scala|ics|vcs|ical|zsh|fish|"
    r"lnk|scr|wsf|wsh|hta|cpl|com|pif|"
    r"pcap|pcapng|cap|etl|evtx|evt|dmp|raw|mem|vmem|lime|e01|aff|dd|"
    r"xlsm|xltm|xlam|docm|dotm|pptm|potm|ppam|sldm|"
    r"elf|so|dylib|class|war|ear|pyc|pyo|whl|egg|"
    r"sig|rules|ioc|stix|taxii|snort|suricata|"
    r"cab|nupkg|appx|msix|appxbundle|dmg|pkg|snap|flatpak)"
)

# Exhaustive TLD list (kept as a single string for regex interpolation)
TLD = (
    r"(?:com|org|top|ga|ml|info|cf|gq|icu|wang|live|cn|online|host|us|tk|fyi|"
    r"buzz|net|io|gov|edu|eu|uk|de|fr|me|es|bid|shop|it|nl|ru|jp|in|br|au|ca|"
    r"mx|nz|tv|cc|co|ro|us|asia|mobi|pro|tel|aero|travel|xyz|dagree|club|"
    r"online|site|store|app|blog|design|tech|guru|ninja|news|media|network|"
    r"agency|digital|email|link|click|world|today|solutions|tools|company|"
    r"photography|tips|technology|works|zone|watch|video|guide|rodeo|life|chat|"
    r"expert|haus|marketing|center|systems|academy|training|services|support|"
    r"education|church|community|foundation|charity|ngo|ong|social|events|"
    r"productions|fun|games|reviews|business|gdn|enterprises|international|"
    r"land|properties|rentals|ventures|holdings|luxury|boutique|accountants|"
    r"agency|associates|attorney|cc|construction|contractors|credit|dentist|"
    r"engineer|equipment|estate|financial|florist|gallery|graphics|law|lawyer|"
    r"management|marketing|media|photography|photos|productions|properties|"
    r"realtor|realty|solutions|studio|systems|technology|ventures|vet|"
    r"veterinarian|aaa|aarp|abb|abbott|abbvie|abc|able|abogado|abudhabi|ac|"
    r"academy|accenture|accountant|accountants|aco|actor|ad|ads|adult|ae|aeg|"
    r"aero|aetna|af|afl|africa|ag|agakhan|agency|ai|aig|airbus|airforce|"
    r"airtel|akdn|al|alibaba|alipay|allfinanz|allstate|ally|alsace|alstom|am|"
    r"amazon|americanexpress|americanfamily|amex|amfam|amica|amsterdam|"
    r"analytics|android|anquan|anz|ao|aol|apartments|app|apple|aq|aquarelle|"
    r"ar|arab|aramco|archi|army|arpa|art|arte|as|asda|asia|associates|at|"
    r"athleta|attorney|au|auction|audi|audible|audio|auspost|author|auto|"
    r"autos|avianca|aw|aws|ax|axa|az|azure|ba|baby|baidu|banamex|"
    r"bananarepublic|band|bank|bar|barcelona|barclaycard|barclays|barefoot|"
    r"bargains|baseball|basketball|bauhaus|bayern|bb|bbc|bbt|bbva|bcg|bcn|bd|"
    r"be|beats|beauty|beer|bentley|berlin|best|bestbuy|bet|bf|bg|bh|bharti|bi|"
    r"bible|bid|bike|bing|bingo|bio|biz|bj|black|blackfriday|blockbuster|blog|"
    r"bloomberg|blue|bm|bms|bmw|bn|bnpparibas|bo|boats|boehringer|bofa|bom|"
    r"bond|boo|book|booking|bosch|bostik|boston|bot|boutique|box|br|bradesco|"
    r"bridgestone|broadway|broker|brother|brussels|bs|bt|build|builders|"
    r"business|buy|buzz|bv|bw|by|bz|bzh|ca|cab|cafe|cal|call|calvinklein|cam|"
    r"camera|camp|canon|capetown|capital|capitalone|car|caravan|cards|care|"
    r"career|careers|cars|casa|case|cash|casino|cat|catering|catholic|cba|cbn|"
    r"cbre|cbs|cc|cd|center|ceo|cern|cf|cfa|cfd|cg|ch|chanel|channel|charity|"
    r"chase|chat|cheap|chintai|christmas|chrome|church|ci|cipriani|circle|"
    r"cisco|citadel|citi|citic|city|cityeats|ck|cl|claims|cleaning|click|"
    r"clinic|clinique|clothing|cloud|club|clubmed|cm|cn|co|coach|codes|coffee|"
    r"college|cologne|com|comcast|commbank|community|company|compare|computer|"
    r"comsec|condos|construction|consulting|contact|contractors|cooking|cool|"
    r"coop|corsica|country|coupon|coupons|courses|cpa|cr|credit|creditcard|"
    r"creditunion|cricket|crown|crs|cruise|cruises|cu|cuisinella|cv|cw|cx|cy|"
    r"cymru|cyou|cz|dabur|dad|dance|data|date|dating|datsun|day|dclk|dds|de|"
    r"deal|dealer|deals|degree|delivery|dell|deloitte|delta|democrat|dental|"
    r"dentist|desi|design|dev|dhl|diamonds|diet|digital|direct|directory|"
    r"discount|discover|dish|diy|dj|dk|dm|dnp|do|docs|doctor|dog|domains|dot|"
    r"download|drive|dtv|dubai|dunlop|dupont|durban|dvag|dvr|dz|earth|eat|ec|"
    r"eco|edeka|edu|education|ee|eg|email|emerck|energy|engineer|engineering|"
    r"enterprises|epson|equipment|er|ericsson|erni|es|esq|estate|et|etisalat|"
    r"eu|eurovision|eus|events|exchange|expert|exposed|express|extraspace|fage|"
    r"fail|fairwinds|faith|family|fan|fans|farm|farmers|fashion|fast|fedex|"
    r"feedback|ferrari|ferrero|fi|fidelity|fido|film|final|finance|financial|"
    r"fire|firestone|firmdale|fish|fishing|fit|fitness|fj|fk|flickr|flights|"
    r"flir|florist|flowers|fly|fm|fo|foo|food|football|ford|forex|forsale|"
    r"forum|foundation|fox|fr|free|fresenius|frl|frogans|frontdoor|frontier|"
    r"ftr|fujitsu|fun|fund|furniture|futbol|fyi|ga|gal|gallery|gallo|gallup|"
    r"game|games|gap|garden|gay|gb|gbiz|gd|gdn|ge|gea|gent|genting|george|gf|"
    r"gg|ggee|gh|gi|gift|gifts|gives|giving|gl|glass|gle|global|globo|gm|"
    r"gmail|gmbh|gmo|gmx|gn|godaddy|gold|goldpoint|golf|goo|goodyear|goog|"
    r"google|gop|got|gov|gp|gq|gr|grainger|graphics|gratis|green|gripe|"
    r"grocery|group|gs|gt|gu|guardian|gucci|guge|guide|guitars|guru|gw|gy|"
    r"hair|hamburg|hangout|haus|hbo|hdfc|hdfcbank|health|healthcare|help|"
    r"helsinki|here|hermes|hiphop|hisamitsu|hitachi|hiv|hk|hkt|hm|hn|hockey|"
    r"holdings|holiday|homedepot|homegoods|homes|homesense|honda|horse|"
    r"hospital|host|hosting|hot|hotels|hotmail|house|how|hr|hsbc|ht|hu|hughes|"
    r"hyatt|hyundai|ibm|icbc|ice|icu|id|ie|ieee|ifm|ikano|il|im|imamat|imdb|"
    r"immo|immobilien|in|inc|industries|infiniti|info|ing|ink|institute|"
    r"insurance|insure|int|international|intuit|investments|io|ipiranga|iq|ir|"
    r"irish|is|ismaili|ist|istanbul|it|itau|itv|jaguar|java|jcb|je|jeep|jetzt|"
    r"jewelry|jio|jll|jm|jmp|jnj|jo|jobs|joburg|jot|joy|jp|jpmorgan|jprs|"
    r"juegos|juniper|kaufen|kddi|ke|kerryhotels|kerrylogistics|"
    r"kerryproperties|kfh|kg|kh|ki|kia|kids|kim|kinder|kindle|kitchen|kiwi|km|"
    r"kn|koeln|komatsu|kosher|kp|kpmg|kpn|kr|krd|kred|kuokgroup|kw|ky|kyoto|"
    r"kz|la|lacaixa|lamborghini|lamer|lancaster|land|landrover|lanxess|"
    r"lasalle|lat|latino|latrobe|law|lawyer|lb|lc|lds|lease|leclerc|lefrak|"
    r"legal|lego|lexus|lgbt|li|lidl|life|lifeinsurance|lifestyle|lighting|"
    r"like|lilly|limited|limo|lincoln|link|lipsy|live|living|lk|llc|llp|loan|"
    r"loans|locker|locus|lol|london|lotte|lotto|love|lpl|lplfinancial|lr|ls|"
    r"lt|ltd|ltda|lu|lundbeck|luxe|luxury|lv|ly|ma|madrid|maif|maison|makeup|"
    r"man|management|mango|map|market|marketing|markets|marriott|marshalls|"
    r"mattel|mba|mc|mckinsey|md|me|med|media|meet|melbourne|meme|memorial|men|"
    r"menu|merckmsd|mg|mh|miami|microsoft|mil|mini|mint|mit|mitsubishi|mk|ml|"
    r"mlb|mls|mm|mma|mn|mo|mobi|mobile|moda|moe|moi|mom|monash|money|monster|"
    r"mormon|mortgage|moscow|moto|motorcycles|mov|movie|mp|mq|mr|ms|msd|mt|"
    r"mtn|mtr|mu|museum|music|mv|mw|mx|my|mz|na|nab|nagoya|name|natura|navy|"
    r"nba|nc|ne|nec|net|netbank|netflix|network|neustar|new|news|next|"
    r"nextdirect|nexus|nf|nfl|ng|ngo|nhk|ni|nico|nike|nikon|ninja|nissan|"
    r"nissay|nl|no|nokia|norton|now|nowruz|nowtv|np|nr|nra|nrw|ntt|nu|nyc|nz|"
    r"obi|observer|office|okinawa|olayan|olayangroup|oldnavy|ollo|om|omega|"
    r"one|ong|onl|online|ooo|open|oracle|orange|org|organic|origins|osaka|"
    r"otsuka|ott|ovh|pa|page|panasonic|paris|pars|partners|parts|party|pay|"
    r"pccw|pe|pet|pf|pfizer|pg|ph|pharmacy|phd|philips|phone|photo|"
    r"photography|photos|physio|pics|pictet|pictures|pid|pin|ping|pink|"
    r"pioneer|pizza|pk|pl|place|play|playstation|plumbing|plus|pm|pn|pnc|pohl|"
    r"poker|politie|porn|post|pr|pramerica|praxi|press|prime|pro|prod|"
    r"productions|prof|progressive|promo|properties|property|protection|pru|"
    r"prudential|ps|pt|pub|pw|pwc|qa|qpon|quebec|quest|racing|radio|re|read|"
    r"realestate|realtor|realty|recipes|red|redstone|redumbrella|rehab|reise|"
    r"reisen|reit|reliance|ren|rent|rentals|repair|report|republican|rest|"
    r"restaurant|review|reviews|rexroth|rich|richardli|ricoh|ril|rio|rip|ro|"
    r"rocher|rocks|rodeo|rogers|room|rs|rsvp|ru|rugby|ruhr|run|rw|rwe|ryukyu|"
    r"sa|saarland|safe|safety|sakura|sale|salon|samsclub|samsung|sandvik|"
    r"sandvikcoromant|sanofi|sap|sarl|sas|save|saxo|sb|sbi|sbs|sc|sca|scb|"
    r"schaeffler|schmidt|scholarships|school|schule|schwarz|science|scot|sd|"
    r"se|search|seat|secure|security|seek|select|sener|services|seven|sew|sex|"
    r"sexy|sfr|sg|sh|shangrila|sharp|shaw|shell|shia|shiksha|shoes|shop|"
    r"shopping|shouji|show|showtime|si|silk|sina|singles|site|sj|sk|ski|skin|"
    r"sky|skype|sl|sling|sm|smart|smile|sn|sncf|so|soccer|social|softbank|"
    r"software|sohu|solar|solutions|song|sony|soy|spa|space|sport|spot|sr|srl|"
    r"ss|st|stada|staples|star|statebank|statefarm|stc|stcgroup|stockholm|"
    r"storage|store|stream|studio|study|style|su|sucks|supplies|supply|"
    r"support|surf|surgery|suzuki|sv|swatch|swiss|sx|sy|sydney|systems|sz|tab|"
    r"taipei|talk|taobao|target|tatamotors|tatar|tattoo|tax|taxi|tc|tci|td|"
    r"tdk|team|tech|technology|tel|temasek|tennis|teva|tf|tg|th|thd|theater|"
    r"theatre|tiaa|tickets|tienda|tips|tires|tirol|tj|tjmaxx|tjx|tk|tkmaxx|"
    r"tl|tm|tmall|tn|to|today|tokyo|tools|top|toray|toshiba|total|tours|town|"
    r"toyota|toys|tr|trade|trading|training|travel|travelers|"
    r"travelersinsurance|trust|trv|tt|tube|tui|tunes|tushu|tv|tvs|tw|tz|ua|"
    r"ubank|ubs|ug|uk|unicom|university|uno|uol|ups|us|uy|uz|va|vacations|"
    r"vana|vanguard|vc|ve|vegas|ventures|verisign|versicherung|vet|vg|vi|"
    r"viajes|video|vig|viking|villas|vin|vip|virgin|visa|vision|viva|vivo|"
    r"vlaanderen|vn|vodka|volkswagen|volvo|vote|voting|voto|voyage|vu|wales|"
    r"walmart|walter|wang|wanggou|watch|watches|weather|weatherchannel|webcam|"
    r"weber|website|wed|wedding|weibo|weir|wf|whoswho|wien|wiki|williamhill|"
    r"win|windows|wine|winners|wme|wolterskluwer|woodside|work|works|world|"
    r"wow|ws|wtc|wtf|xbox|xerox|xfinity|xihuan|xin|"
    r"xn--11b4c3d|xn--1ck2e1b|xn--1qqw23a|xn--2scrj9c|xn--30rr7y|"
    r"xn--3bst00m|xn--3ds443g|xn--3e0b707e|xn--3hcrj9c|xn--3pxu8k|"
    r"xn--42c2d9a|xn--45br5cyl|xn--45brj9c|xn--45q11c|xn--4dbrk0ce|"
    r"xn--4gbrim|xn--54b7fta0cc|xn--55qw42g|xn--55qx5d|"
    r"xn--5su34j936bgsg|xn--5tzm5g|xn--6frz82g|xn--6qq986b3xl|"
    r"xn--80adxhks|xn--80ao21a|xn--80aqecdr1a|xn--80asehdb|xn--80aswg|"
    r"xn--8y0a063a|xn--90a3ac|xn--90ae|xn--90ais|xn--9dbq2a|xn--9et52u|"
    r"xn--9krt00a|xn--b4w605ferd|xn--bck1b9a5dre4c|xn--c1avg|xn--c2br7g|"
    r"xn--cck2b3b|xn--cckwcxetd|xn--cg4bki|xn--clchc0ea0b2g2a9gcd|"
    r"xn--czr694b|xn--czrs0t|xn--czru2d|xn--d1acj3b|xn--d1alf|xn--e1a4c|"
    r"xn--eckvdtc9d|xn--efvy88h|xn--fct429k|xn--fhbei|xn--fiq228c5hs|"
    r"xn--fiq64b|xn--fiqs8s|xn--fiqz9s|xn--fjq720a|xn--flw351e|"
    r"xn--fpcrj9c3d|xn--fzc2c9e2c|xn--fzys8d69uvgm|xn--g2xx48c|"
    r"xn--gckr3f0f|xn--gecrj9c|xn--gk3at1e|xn--h2breg3eve|xn--h2brj9c|"
    r"xn--h2brj9c8c|xn--hxt814e|xn--i1b6b1a6a2e|xn--imr513n|xn--io0a7i|"
    r"xn--j1aef|xn--j1amh|xn--j6w193g|xn--jlq480n2rg|xn--jvr189m|"
    r"xn--kcrx77d1x4a|xn--kprw13d|xn--kpry57d|xn--kput3i|xn--l1acc|"
    r"xn--lgbbat1ad8j|xn--mgb9awbf|xn--mgba3a3ejt|xn--mgba3a4f16a|"
    r"xn--mgba7c0bbn0a|xn--mgbaakc7dvf|xn--mgbaam7a8h|xn--mgbab2bd|"
    r"xn--mgbah1a3hjkrd|xn--mgbai9azgqp6j|xn--mgbayh7gpa|xn--mgbbh1a|"
    r"xn--mgbbh1a71e|xn--mgbc0a9azcg|xn--mgbca7dzdo|xn--mgbcpq6gpa1a|"
    r"xn--mgberp4a5d4ar|xn--mgbgu82a|xn--mgbi4ecexp|xn--mgbpl2fh|"
    r"xn--mgbt3dhd|xn--mgbtx2b|xn--mgbx4cd0ab|xn--mix891f|xn--mk1bu44c|"
    r"xn--mxtq1m|xn--ngbc5azd|xn--ngbe9e0a|xn--ngbrx|xn--node|xn--nqv7f|"
    r"xn--nqv7fs00ema|xn--nyqy26a|xn--o3cw4h|xn--ogbpf8fl|xn--otu796d|"
    r"xn--p1acf|xn--p1ai|xn--pgbs0dh|xn--pssy2u|xn--q7ce6a|xn--q9jyb4c|"
    r"xn--qcka1pmc|xn--qxa6a|xn--qxam|xn--rhqv96g|xn--rovu88b|"
    r"xn--rvc1e0am3e|xn--s9brj9c|xn--ses554g|xn--t60b56a|xn--tckwe|"
    r"xn--tiq49xqyj|xn--unup4y|xn--vermgensberater-ctb|"
    r"xn--vermgensberatung-pwb|xn--vhquv|xn--vuq861b|"
    r"xn--w4r85el8fhu5dnra|xn--w4rs40l|xn--wgbh1c|xn--wgbl6a|xn--xhq521b|"
    r"xn--xkc2al3hye2a|xn--xkc2dl3a5ee0h|xn--y9a3aq|xn--yfro4i67o|"
    r"xn--ygbi2ammx|xn--zfr164b|xxx|xyz|yachts|yahoo|yamaxun|yandex|ye|"
    r"yodobashi|yoga|yokohama|you|youtube|yt|yun|za|zappos|zara|zero|zip|zm|"
    r"zone|zuerich|zw)"
)


# ---------------------------------------------------------------------------
# Compiled IOC regex patterns
# ---------------------------------------------------------------------------

IOC_PATTERNS = {

    # =======================================================================
    # Network Indicators
    # =======================================================================

    # IPv4 — standard and defanged with [.]
    "IPv4": re.compile(
        r"\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"(?:\.|\[\.\])(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    ),

    # IPv4 defanged with parentheses: 192(.)168(.)1(.)1
    "IPv4 (defanged)": re.compile(
        r"\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"\(\.\)(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"\(\.\)(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"\(\.\)(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
    ),

    # IPv4 with port: 192.168.1.1:8080
    "IPv4:Port": re.compile(
        r"\b((?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"(?:\.|\[\.\])(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"(?:\.|\[\.\])(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"(?:\.|\[\.\])(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))"
        r":(\d{1,5})\b"
    ),

    # CIDR notation: 10.0.0.0/24
    "CIDR": re.compile(
        r"\b((?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
        r"\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))"
        r"/([12]?\d|3[0-2])\b"
    ),

    # IPv6 - disabled by default due to noise; uncomment to enable
    # "IPv6": re.compile(IPV6_PATTERN_STR, re.IGNORECASE),

    # ASN numbers: AS13335, AS4134
    "ASN": re.compile(r"\bAS(\d{1,10})\b"),

    # --- Domains ---

    "Domains": re.compile(
        r"(?<![@a-zA-Z0-9._%+-])([a-zA-Z0-9\-]+(?:\.|\[\.\])"
        + TLD
        + r")\b"
    ),

    "Sub Domains": re.compile(
        r"(?<![@a-zA-Z0-9._%+-])"
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.|\[\.]))+[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.|\[\.])[a-zA-Z]{2,}"
    ),

    # Domains defanged with [dot] notation: evil[dot]com, evil[dot]com[dot]br
    "Domains (defanged [dot])": re.compile(
        r"\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\s*\[dot\]\s*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+\b",
        re.IGNORECASE,
    ),

    # Domains defanged with (dot) notation: evil(dot)com
    "Domains (defanged (dot))": re.compile(
        r"\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\s*\(dot\)\s*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+\b",
        re.IGNORECASE,
    ),

    # Domains defanged with (.) notation: evil(.)com, evil(.)com(.)br
    "Domains (defanged (.))": re.compile(
        r"\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\(\.\)[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+\b",
    ),

    # --- URLs ---

    "URLs": re.compile(
        r"((?!.*[a-zA-Z0-9]{16,}(\[\.\]|\.)onion\/)"
        r"[fhstu]\S\S?[px]s?(?::\/\/|:\\\\|\[:\]\/\/|\[:\/\/\]|:?__)"
        r"(?:\x20|" + SEPARATOR_DEFANGS + r")*"
        r"\w\S+?(?:\x20[\/\.][^\.\/\s]\S*?)*)(?=\s|[^\x00-\x7F]|$)",
        re.IGNORECASE | re.VERBOSE | re.UNICODE,
    ),

    "IP URL": re.compile(
        r"hxxps?:\/\/(?:\d{1,3}\.|\[\.\])?"
        r"(?:\d{1,3}\.|\[\.\])?(?:\d{1,3}\.|\[\.\])?"
        r"\d{1,3}(?:\[\.\]\d{1,3})?\/\d+\/[a-f0-9]+"
    ),

    # Defanged URLs with [.] notation and paths
    # Matches: domain[.]com[.]br/path/file.ext, sub[.]domain[.]com/path
    "Defanged URLs": re.compile(
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"\[\.\]){1,10}"
        r"[a-zA-Z]{2,}"
        r"(?:/[^\s<>\"',;)\]]*)?",
        re.IGNORECASE,
    ),

    # =======================================================================
    # Hashes & Fingerprints
    # =======================================================================

    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "sha512": re.compile(r"\b[A-Fa-f0-9]{128}\b"),
    "SS-Deep": re.compile(r"\b(?=.{60})\d+:[A-Za-z0-9/+]+:[A-Za-z0-9/+]+\b"),

    # JARM fingerprint (62 hex chars — TLS server fingerprint)
    "JARM": re.compile(r"\b[a-fA-F0-9]{62}\b"),

    # JA3/JA3S — TLS client/server fingerprints (labeled MD5 hashes)
    "JA3/JA3S": re.compile(
        r"\bja3s?\s*[:=]\s*[a-fA-F0-9]{32}\b",
        re.IGNORECASE,
    ),

    # JA4+ — next-gen TLS fingerprints (JA4, JA4S, JA4H, JA4L, JA4X, JA4SSH)
    # Format: alphanumeric_hex_hex with varying segment lengths across JA4 subtypes
    "JA4+": re.compile(
        r"(?:\bja4[shxl]*\s*[:=]\s*)?[a-z][a-z0-9]{7,14}_[a-f0-9]{4,12}_[a-f0-9]{4,12}\b",
        re.IGNORECASE,
    ),

    # IMPHASH — PE import hash (labeled to distinguish from plain MD5)
    "IMPHASH": re.compile(
        r"(?:imphash|import\s*hash)\s*[:=]\s*[a-fA-F0-9]{32}\b",
        re.IGNORECASE,
    ),

    # =======================================================================
    # Vulnerability / Technique Identifiers
    # =======================================================================

    "CVEs": re.compile(
        r"(?:CVE-\d{4}-\d{4,}|CVE\s*[\[\(]\s*\d{4}-\d{4,}\s*[\]\)])"
    ),

    # MITRE ATT&CK IDs: T1059, T1059.001, TA0001, G0016, S0154, M1036
    "MITRE ATT&CK": re.compile(
        r"\b((?:T[1-9]\d{3}(?:\.\d{3})?)|(?:TA\d{4})|(?:G\d{4})|(?:S\d{4})|(?:M\d{4}))\b"
    ),

    # Threat group identifiers: APT28, FIN7, UNC2452, DEV-0537, TA505, TEMP.Veles
    # TA requires 2-3 digits to avoid collision with MITRE ATT&CK TA#### tactic IDs
    "Threat Group IDs": re.compile(
        r"\b(?:(?:APT|FIN|UNC|DEV)\s*-?\s*\d{1,5}|TA\s*-?\s*\d{2,3}|TEMP\.\w+)\b",
        re.IGNORECASE,
    ),

    # STIX 2.x structured threat intel object IDs
    "STIX IDs": re.compile(
        r"\b(?:attack-pattern|campaign|course-of-action|grouping|identity|"
        r"indicator|infrastructure|intrusion-set|location|malware(?:-analysis)?|"
        r"note|observed-data|opinion|relationship|report|sighting|"
        r"threat-actor|tool|vulnerability)"
        r"--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    ),

    # Snort/Suricata signature IDs
    "Snort/Suricata SIDs": re.compile(
        r"\bsid\s*[:=]\s*(\d{4,10})\s*;?",
        re.IGNORECASE,
    ),

    # =======================================================================
    # File System Indicators
    # =======================================================================

    # File names — matches both quoted ("payload.exe") and unquoted (payload.exe)
    # as well as defanged extensions (payload[.]exe)
    "File Names": re.compile(
        (
            # Inside quotes: "file.exe" or 'file.dll'
            r'(?<=[\"\'])[^\"\'\s\\/:*?<>|]+(?:\.|\[\.\]){0}(?=[\"\'])'
            r"|"
            # Outside quotes: bare file.exe in text
            r'(?<![\"\'])\b[^\'" \t\n\r\f\v/\-\\]+?(?:\.|\[\.\]){0}\b(?![\"\'])'
        ).format(FILE_EXTENSIONS),
        re.VERBOSE,
    ),

    # Windows file paths: C:\Users\..., D:\Windows\..., %windir%\..., %TEMP%\...
    # Supports spaces in directory segments (e.g. "Start Menu", "Windows NT")
    # Supports consecutive env vars: %HOMEDRIVE%%HOMEPATH%\...
    # Supports both single \ and escaped \\ path separators (JSON, log output)
    # Strategy: directory segments (between \'s) may contain spaces; the final
    # segment (filename) may NOT contain spaces so we stop cleanly.
    "Windows File Paths": re.compile(
        r"(?:[A-Za-z]:|(?:%[a-zA-Z_()][a-zA-Z0-9_()]*%)+)"       # drive letter or env var(s)
        r"(?:\\{1,2}[^\n\r<>\"'|*?\\:]*[^\s<>\"'|*?\\:])*"        # dir segments (\ or \\)
        r"\\{1,2}[^\s<>\"'|*?\\:]+"                                # final segment: no spaces/colons
    ),

    # UNC paths: \\server\share\path\file.ext
    "UNC Paths": re.compile(
        r"\\\\[a-zA-Z0-9._\-]+(?:\\[^\s<>\"',:;|*?]+)+"
    ),

    # PDB debug paths embedded in PE binaries — malware attribution indicator
    "PDB Paths": re.compile(
        r"[A-Za-z]:\\[^\s<>\"'|*?]*?\.pdb\b"
    ),

    # Named pipes — inter-process communication, common in RAT/C2 tools
    "Named Pipes": re.compile(
        r"\\\\\.\\pipe\\[^\s<>\"',;)]{3,120}"
    ),

    # =======================================================================
    # Identity & Communication
    # =======================================================================

    "Email Addresses": re.compile(
        r"([a-z0-9_.+-]+[\(\[{\x20]*"
        r"(?:(?:(?:\x20*" + SEPARATOR_DEFANGS + r"\x20*)*\.(?:\x20*"
        + SEPARATOR_DEFANGS + r"\x20*)*|\W+dot\W+)[a-z0-9-]+?)*"
        r"[a-z0-9_.+-]*[\(\[{\x20]*(?:@|\Wat\W)[\)\]}\x20]*"
        r"[a-z0-9-]+(?:(?:(?:\x20*" + SEPARATOR_DEFANGS + r"\x20*)*\.(?:\x20*"
        + SEPARATOR_DEFANGS + r"\x20*)*|\W+dot\W+)[a-z0-9-]+?)+)"
        + END_PUNCTUATION + r"(?=\s|$)",
        re.IGNORECASE | re.VERBOSE | re.UNICODE,
    ),

    # =======================================================================
    # Windows Registry
    # =======================================================================

    # Short-form registry keys: HKLM\..., HKCU\..., HKCR\..., HKU\...
    # Supports spaces in key names (e.g. "Windows NT", "User Shell Folders")
    "Registry": re.compile(
        r"\b((?:HKLM|HKCU|HKCR|HKU|HKCC)"
        r"(?:\\[A-Za-z0-9\-_.][A-Za-z0-9\-_. ]*[A-Za-z0-9\-_.]"   # segments with spaces
        r"|\\[A-Za-z0-9\-_.])+)"                                    # single-char segments
    ),

    # Long-form registry keys: HKEY_LOCAL_MACHINE\..., HKEY_CURRENT_USER\..., etc.
    "Registry (Long Form)": re.compile(
        r"\b((?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
        r"HKEY_USERS|HKEY_CURRENT_CONFIG)"
        r"(?:\\[A-Za-z0-9\-_.][A-Za-z0-9\-_. ]*[A-Za-z0-9\-_.]"
        r"|\\[A-Za-z0-9\-_.])+)"
    ),

    # =======================================================================
    # Hardware / Network Layer
    # =======================================================================

    "Mac Address": re.compile(
        r"\b(?:[A-Fa-f0-9]{2}([-:]))(?:[A-Fa-f0-9]{2}\1){4}[A-Fa-f0-9]{2}\b"
    ),

    # =======================================================================
    # Cryptocurrency Addresses
    # =======================================================================

    # Bitcoin legacy (1... or 3...) — P2PKH and P2SH
    "Bitcoin Addresses": re.compile(r"\b[13][a-km-zA-HJ-NP-Z0-9]{26,33}\b"),

    # Bitcoin bech32 (bc1...) — SegWit
    "Bitcoin Bech32": re.compile(r"\bbc1[a-zA-HJ-NP-Za-km-z0-9]{25,87}\b"),

    # Ethereum addresses (0x followed by 40 hex chars)
    "Ethereum Addresses": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),

    # Monero addresses (95 chars starting with 4 or 8)
    "Monero Addresses": re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),

    # Monero integrated addresses (106 chars — includes embedded payment ID)
    "Monero Integrated Addresses": re.compile(
        r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{104}\b"
    ),

    # =======================================================================
    # Dark Web
    # =======================================================================

    "Dark Web": re.compile(r"[a-z2-7]{2,56}\.onion\b"),

    # =======================================================================
    # Detection Rules
    # =======================================================================

    "Yara Rules": re.compile(
        r"(?:^|\s)"
        r"((?:\s*?import\s+?\"[^\r\n]*?[\r\n]+"
        r"|\s*?include\s+?\"[^\r\n]*?[\r\n]+"
        r"|\s*?//[^\r\n]*[\r\n]+"
        r"|\s*?/\*.*?\*/\s*?)*"
        r"(?:\s*?private\s+|\s*?global\s+)*"
        r"rule\s*?\w+\s*?(?::[\s\w]+)?\s+\{.*?condition\s*?:.*?\s*\})"
        r"(?:$|\s)",
        re.MULTILINE | re.DOTALL | re.VERBOSE,
    ),

    # Sigma rules (YAML-based generic detection) — matches the full rule block
    # Requires title: + detection: section (the two mandatory fields)
    # Captures everything from title: through post-detection fields (level, tags, etc.)
    # until a blank line, another title:, a section separator, or EOF
    "Sigma Rules": re.compile(
        r"(?:^|\n)"
        r"(title\s*:[^\n]+\n"                       # title: ... (required)
        r"(?:[ \t]+[^\n]+\n|[a-z_]+\s*:[^\n]*\n)*?" # intermediate YAML fields
        r"detection\s*:\s*\n"                         # detection: (required)
        r"(?:[ \t]+[^\n]+\n)*"                        # indented detection body
        r"(?:[a-z_]+\s*:[^\n]*\n"                     # post-detection top-level fields
        r"(?:[ \t]+[^\n]+\n)*)*)",                    # their indented sub-items
        re.MULTILINE,
    ),

    # Snort/Suricata full rules — alert/drop/pass/log/reject with protocol + direction + options
    # Uses .*? instead of [^)]* to handle parentheses inside pcre/content options
    "Snort/Suricata Rules": re.compile(
        r"((?:alert|drop|pass|log|reject|sdrop)"       # action keyword
        r"\s+(?:tcp|udp|icmp|ip|http|dns|tls|ftp|smtp|ssh)"  # protocol
        r"\s+\S+\s+\S+"                                # src_addr src_port
        r"\s+[-<>]{2}\s+"                               # direction operator -> or <>
        r"\S+\s+\S+"                                    # dst_addr dst_port
        r"\s*\(.*?"                                     # options block open (handles nested parens)
        r"sid\s*:\s*\d+"                                # must contain sid:NNNNN
        r".*?\))",                                      # rest of options + close paren
        re.IGNORECASE,
    ),

    # Sigma rule IDs — standalone UUIDs from Sigma rules (id: field)
    # These appear in sigma rule references and sigma-cli output
    "Sigma Rule IDs": re.compile(
        r"\bsigma[-_](?:id|rule)\s*[:=]\s*"
        r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b",
        re.IGNORECASE,
    ),

    # ModSecurity / WAF rules — SecRule directives with id: and operators
    # No line-start anchor so rules embedded in prose context are also matched
    "ModSecurity Rules": re.compile(
        r"(SecRule\s+\S+"                              # SecRule VARIABLE
        r"\s+\"@\w+\s+[^\"]+\""                       # "@operator pattern"
        r"\s+\"[^\"]*id:\d+[^\"]*\")",                 # "id:NNNNN,..."
        re.IGNORECASE,
    ),

    # =======================================================================
    # Malware Behavior Indicators
    # =======================================================================

    # Mutex / Mutant names — malware uses unique mutexes to prevent re-infection
    "Mutex Names": re.compile(
        r"(?:(?:Mutex|Mutant)\s*[:=]\s*)"
        r"(?:Global\\|Local\\|\\BaseNamedObjects\\)?"
        r"[^\s,;\"'<>]{3,120}",
        re.IGNORECASE,
    ),

    # User-Agent strings — identifies C2 beaconing and attacker tooling
    "User-Agent Strings": re.compile(
        r"User-Agent\s*:\s*([^\r\n]{1,512})",
        re.IGNORECASE,
    ),

    # Scheduled task creation commands — persistence mechanism (T1053.005)
    "Scheduled Tasks": re.compile(
        r"schtasks(?:\.exe)?\s+/create\s+[^\r\n]+",
        re.IGNORECASE,
    ),

    # Windows service manipulation — persistence via sc create/config
    "Windows Service Commands": re.compile(
        r"(?:sc\s+(?:create|config|start|stop|delete|query)\s+\S+[^\r\n]*"
        r"|New-Service\s+[^\r\n]+)",
        re.IGNORECASE,
    ),

    # PowerShell encoded commands — obfuscated payload delivery
    "PowerShell Encoded Commands": re.compile(
        r"(?:powershell(?:\.exe)?\s+(?:[^\r\n]*?\s)?)"
        r"(?:-(?:e(?:nc(?:odedcommand)?)?|ec)\s+)"
        r"([A-Za-z0-9+/=]{20,})",
        re.IGNORECASE,
    ),

    # =======================================================================
    # Infrastructure Tracking
    # =======================================================================

    # Google Analytics tracker IDs — infrastructure clustering
    "Google Analytics IDs": re.compile(
        r"\b(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{10,12})\b"
    ),

    # Google Adsense publisher IDs — monetization tracking
    "Adsense Publisher IDs": re.compile(
        r"\bpub-\d{16}\b"
    ),

    # AWS S3 bucket references — cloud incident indicators
    "AWS S3 References": re.compile(
        r"(?:s3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](?:/\S*)?)"
        r"|(?:https?://[a-z0-9.\-]+\.s3[.\-][a-z0-9.\-]*amazonaws\.com\S*)"
        r"|(?:https?://s3[.\-][a-z0-9.\-]*amazonaws\.com/[a-z0-9.\-]+\S*)"
        r"|(?:arn:aws:s3:::[a-z0-9.\-]{3,63})",
        re.IGNORECASE,
    ),

    # Abuse.ch references — URLhaus, MalBazaar, ThreatFox, etc.
    "Abuse.ch References": re.compile(
        r"https?://(?:urlhaus|bazaar|threatfox|sslbl|feodotracker)\.abuse\.ch/\S+",
        re.IGNORECASE,
    ),
}
