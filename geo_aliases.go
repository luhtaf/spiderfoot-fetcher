package main

// exactAliases is a 1:1 port of EXACT_ALIASES from updatelat.py: a mapping from
// an organization name (original or cleaned) to an ordered list of geocode
// query candidates tried before the generic candidate generators.
var exactAliases = map[string][]string{
	"Bappenas": {"Badan Perencanaan Pembangunan Nasional"},
	"Badan Nasional Pencarian Dan Pertolongan": {
		"BASARNAS, Jakarta, Indonesia",
		"Badan Nasional Pencarian dan Pertolongan, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Badan Pengendalian Pembangunan Dan Investasi": {
		"BKPM, Jakarta, Indonesia",
		"Kementerian Investasi dan Hilirisasi, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Badan Pengaturan Badan Usaha Milik Negara": {
		"Kementerian BUMN, Jakarta, Indonesia",
		"Kementerian Badan Usaha Milik Negara, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Badan Pengkajian Dan Penerapan Teknologi": {
		"BPPT, Jakarta, Indonesia",
		"Badan Riset dan Inovasi Nasional, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Badan Pangan Nasional": {
		"Bapanas, Jakarta, Indonesia",
		"National Food Agency Indonesia",
		"Jakarta, Indonesia",
	},
	"Badan Pengusahaan Kawasan Perdagangan Bebas Dan Pelabuhan Bebas Batam": {
		"BP Batam, Batam, Kepulauan Riau, Indonesia",
		"Badan Pengusahaan Batam, Batam, Kepulauan Riau, Indonesia",
		"Batam, Kepulauan Riau, Indonesia",
	},
	"Badan Perencanaan Pembangunan Nasional": {
		"Bappenas, Jakarta, Indonesia",
		"Kementerian PPN/Bappenas, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Badan Perlindungan Pekerja Migran Indonesia": {
		"BP2MI, Jakarta, Indonesia",
		"Badan Pelindungan Pekerja Migran Indonesia, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Badan Siber Dan Sandi Negara": {
		"BSSN, Depok, Jawa Barat, Indonesia",
		"Badan Siber dan Sandi Negara, Depok, Jawa Barat, Indonesia",
		"Depok, Jawa Barat, Indonesia",
	},
	"Badan Standardisasi Nasional": {
		"BSN, Jakarta, Indonesia",
		"Badan Standardisasi Nasional, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Bakti Komdigi": {
		"BAKTI Kominfo, Jakarta, Indonesia",
		"Badan Aksesibilitas Telekomunikasi dan Informasi, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Bph Migas":      {"BPH Migas"},
	"Bpjs Kesehatan": {"BPJS Kesehatan"},
	"Desa Air Berudang": {
		"Air Berudang, Tapaktuan, Aceh Selatan, Aceh, Indonesia",
		"Tapaktuan, Aceh Selatan, Aceh, Indonesia",
	},
	"Desa Buninagara": {
		"Buninagara, Kutawaringin, Kabupaten Bandung, Jawa Barat, Indonesia",
		"Kutawaringin, Kabupaten Bandung, Jawa Barat, Indonesia",
	},
	"Desa Cibodas Kutawaringin": {
		"Cibodas, Kutawaringin, Kabupaten Bandung, Jawa Barat, Indonesia",
		"Kutawaringin, Kabupaten Bandung, Jawa Barat, Indonesia",
	},
	"Desa Jatisari Kutawaringin": {
		"Jatisari, Kutawaringin, Kabupaten Bandung, Jawa Barat, Indonesia",
		"Kutawaringin, Kabupaten Bandung, Jawa Barat, Indonesia",
	},
	"Desa Jelegong Kutawaringin": {
		"Jelegong, Kutawaringin, Kabupaten Bandung, Jawa Barat, Indonesia",
		"Kutawaringin, Kabupaten Bandung, Jawa Barat, Indonesia",
	},
	"Desa Kutawaringin": {
		"Kutawaringin, Kabupaten Bandung, Jawa Barat, Indonesia",
	},
	"Desa Pamekaran": {
		"Pamekaran, Soreang, Kabupaten Bandung, Jawa Barat, Indonesia",
		"Soreang, Kabupaten Bandung, Jawa Barat, Indonesia",
	},
	"Desa Panyirapan": {
		"Panyirapan, Soreang, Kabupaten Bandung, Jawa Barat, Indonesia",
		"Soreang, Kabupaten Bandung, Jawa Barat, Indonesia",
	},
	"Dewan Ketahanan Nasional": {
		"Wantannas, Jakarta, Indonesia",
		"Dewan Ketahanan Nasional, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Insw": {"Indonesia National Single Window"},
	"Kantor Staf Presiden": {
		"Gedung Bina Graha, Jakarta, Indonesia",
		"Istana Kepresidenan Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kbri Bandar Sri Begawan": {
		"Kedutaan Besar Republik Indonesia Bandar Seri Begawan",
		"Embassy of Indonesia Bandar Seri Begawan, Brunei",
		"Bandar Seri Begawan, Brunei",
	},
	"Kbri Tokyo": {
		"Kedutaan Besar Republik Indonesia Tokyo",
		"Embassy of Indonesia Tokyo, Japan",
		"Tokyo, Japan",
	},
	"Kejaksanaan Negeri Seluma": {
		"Kejaksaan Negeri Seluma, Kabupaten Seluma, Bengkulu, Indonesia",
		"Seluma, Bengkulu, Indonesia",
	},
	"Kementerian Agraria Dan Tata Ruang/Badan Pertanahan Nasional": {
		"Kementerian ATR BPN, Jakarta, Indonesia",
		"Badan Pertanahan Nasional, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Agraria Dan Tata Ruang/badan Pertanahan Nasional": {
		"Kementerian ATR BPN, Jakarta, Indonesia",
		"Badan Pertanahan Nasional, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Imigrasi Dan Pemasyarakatan": {
		"Direktorat Jenderal Imigrasi, Jakarta, Indonesia",
		"Kementerian Imigrasi dan Pemasyarakatan, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Imigrasi Dan Permasyarakatan": {
		"Direktorat Jenderal Imigrasi, Jakarta, Indonesia",
		"Kementerian Imigrasi dan Pemasyarakatan, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Investasi/badan Koordinasi Penanaman Modal": {
		"BKPM, Jakarta, Indonesia",
		"Kementerian Investasi BKPM, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Investasi/Badan Koordinasi Penanaman Modal": {
		"BKPM, Jakarta, Indonesia",
		"Kementerian Investasi BKPM, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Koordinator Bidang Hukum Hak Asasi Manusia Imigrasi Dan Pemasyarakatan": {
		"Kementerian Koordinator Bidang Hukum HAM Imigrasi dan Pemasyarakatan, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Koordinator Bidang Hukum Ham Dan Imipas": {
		"Kementerian Koordinator Bidang Hukum HAM Imigrasi dan Pemasyarakatan, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Koordinator Bidang Pmk": {
		"Kementerian Koordinator Bidang Pembangunan Manusia dan Kebudayaan, Jakarta, Indonesia",
		"Kemenko PMK, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Koordinator Bidang Politik Hukum Dan Keamanan": {
		"Kementerian Koordinator Bidang Politik Hukum dan Keamanan, Jakarta, Indonesia",
		"Kemenko Polhukam, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Koperasi Dan Usaha Kecil Dan Menengah": {
		"Kementerian Koperasi dan UKM, Jakarta, Indonesia",
		"Kemenkop UKM, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Pariwisata Dan Ekonomi Kreatif": {
		"Kementerian Pariwisata dan Ekonomi Kreatif, Jakarta, Indonesia",
		"Kemenparekraf, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Pendidikan Dasar Dan Menengah": {
		"Kementerian Pendidikan Dasar dan Menengah, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Pendidikan Tinggi Sains Dan Teknologi": {
		"Kementerian Pendidikan Tinggi Sains dan Teknologi, Jakarta, Indonesia",
		"Kemdiktisaintek, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kemeterian Pendidikan Tinggi Sains Dan Teknologi": {
		"Kementerian Pendidikan Tinggi Sains dan Teknologi, Jakarta, Indonesia",
		"Kemdiktisaintek, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kementerian Perumahan Dan Kawasan Permukiman": {
		"Kementerian Perumahan dan Kawasan Permukiman, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Komisi Informasi Pusat": {
		"Komisi Informasi Pusat, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Kjri New York": {
		"Konsulat Jenderal Republik Indonesia New York",
		"Consulate General of Indonesia New York, United States",
		"New York, United States",
	},
	"Lembaga Penjamin Simpanan": {
		"Lembaga Penjamin Simpanan, Jakarta, Indonesia",
		"LPS, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Lembaga Perlindungan Saksi Dan Korban": {
		"Lembaga Perlindungan Saksi dan Korban, Jakarta, Indonesia",
		"LPSK, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Skk Migas":         {"SKK Migas"},
	"Mahkamah Agung Ri": {"Mahkamah Agung Republik Indonesia"},
	"Mahkamah Syariyah Singkil": {
		"Mahkamah Syar'iyah Singkil, Aceh Singkil, Aceh, Indonesia",
		"Singkil, Aceh Singkil, Aceh, Indonesia",
	},
	"Perpustakaan Nasional Ri": {"Perpustakaan Nasional Republik Indonesia"},
	"Pemerintah Kabupaten Aceh Jaya": {
		"Kabupaten Aceh Jaya, Aceh, Indonesia",
	},
	"Pemerintah Kabupaten Bolmong": {
		"Kabupaten Bolaang Mongondow, Sulawesi Utara, Indonesia",
	},
	"Pemerintah Kabupaten Buol": {
		"Kabupaten Buol, Sulawesi Tengah, Indonesia",
	},
	"Pemerintah Kabupaten Konawe Utara": {
		"Kabupaten Konawe Utara, Sulawesi Tenggara, Indonesia",
	},
	"Pemerintah Kabupaten Mandailing Natal": {
		"Kabupaten Mandailing Natal, Sumatera Utara, Indonesia",
	},
	"Pemerintah Kabupaten Pacitan": {
		"Kabupaten Pacitan, Jawa Timur, Indonesia",
	},
	"Pemerintah Kabupaten Sidoarjo": {
		"Kabupaten Sidoarjo, Jawa Timur, Indonesia",
	},
	"Pemerintah Kabupaten Teluk Bintuni": {
		"Kabupaten Teluk Bintuni, Papua Barat, Indonesia",
	},
	"Pemkab Sanggas": {
		"Kabupaten Sanggau, Kalimantan Barat, Indonesia",
	},
	"Pengadilan Agama Ternate": {
		"Pengadilan Agama Ternate, Kota Ternate, Maluku Utara, Indonesia",
		"Ternate, Maluku Utara, Indonesia",
	},
	"Pengadilan Negeri Gresik": {
		"Pengadilan Negeri Gresik, Kabupaten Gresik, Jawa Timur, Indonesia",
		"Gresik, Jawa Timur, Indonesia",
	},
	"Pengadilan Negeri Kuala Kurun": {
		"Pengadilan Negeri Kuala Kurun, Gunung Mas, Kalimantan Tengah, Indonesia",
		"Kuala Kurun, Gunung Mas, Kalimantan Tengah, Indonesia",
	},
	"Pengadilan Negeri Mungkid": {
		"Pengadilan Negeri Mungkid, Kabupaten Magelang, Jawa Tengah, Indonesia",
		"Mungkid, Kabupaten Magelang, Jawa Tengah, Indonesia",
	},
	"Pengadilan Negeri Pacitan": {
		"Pengadilan Negeri Pacitan, Kabupaten Pacitan, Jawa Timur, Indonesia",
		"Pacitan, Jawa Timur, Indonesia",
	},
	"Pengadilan Negeri Solok": {
		"Pengadilan Negeri Solok, Sumatera Barat, Indonesia",
		"Solok, Sumatera Barat, Indonesia",
	},
	"Pengadilan Negeri Tamiang Layang": {
		"Pengadilan Negeri Tamiang Layang, Barito Timur, Kalimantan Tengah, Indonesia",
		"Tamiang Layang, Barito Timur, Kalimantan Tengah, Indonesia",
	},
	"Pengadilan Tinggi Agama Ambon": {
		"Pengadilan Tinggi Agama Ambon, Maluku, Indonesia",
		"Ambon, Maluku, Indonesia",
	},
	"Pusat Pelaporan Dan Analisis Transaksi Keuangan": {
		"PPATK, Jakarta, Indonesia",
		"Pusat Pelaporan dan Analisis Transaksi Keuangan, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Sekretariat Wakil Presiden": {
		"Istana Wakil Presiden, Jakarta, Indonesia",
		"Sekretariat Wakil Presiden, Jakarta, Indonesia",
		"Jakarta, Indonesia",
	},
	"Lembaga Ketahanan Nasional Ri": {
		"Lembaga Ketahanan Nasional Republik Indonesia",
		"Lemhannas Republik Indonesia",
	},
	"Nanggroe Aceh Darussalam": {"Aceh"},
	"Provinsi Yogyakarta":      {"Daerah Istimewa Yogyakarta"},
}
