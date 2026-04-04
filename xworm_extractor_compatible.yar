rule XWorm_Extractor_Compatible {
	meta:
		description   = "XWorm — AES-256-ECB/MD5 encrypted config, compatible with xworm_extractor.py"
		author        = "Luis Suastegui"
		date          = "2026-04-02"
		version       = "1.0"
		sample_sha256 = "cdde3b2650c951e774a8694208c0d151e91b40db5d21da3d790d88ebd702edec"
		reference     = "xworm_extractor.py — static .NET #US stream config extractor"
		tlp           = "WHITE"
		confidence    = "high"
	strings:
		$bsjb = { 42 53 4A 42 }  // "BSJB"

		$s_algo_aes    = "AlgorithmAES" ascii fullword
		$s_rijndael    = "RijndaelManaged" ascii fullword
		$s_md5         = "MD5CryptoServiceProvider" ascii fullword
		$s_usbnm       = "USBNM" ascii fullword
		$s_client_sock = "ClientSocket" ascii fullword

		$us_version    = "XWorm" wide
		$us_ping       = "PING!" wide
		$us_uninstall  = "uninstall" wide
		$us_pcshutdown = "PCShutdown" wide
		$us_startddos  = "StartDDos" wide
	condition:
		uint16(0) == 0x5A4D
		and filesize >= 20KB
		and filesize < 500KB

		and $bsjb

		and $s_algo_aes
		and $s_rijndael
		and $s_md5

		and $s_usbnm

		and $s_client_sock

		and (
			($us_version and $us_ping)
			or ($us_version and $us_uninstall)
			or ($us_version and $us_pcshutdown)
			or ($us_version and $us_startddos)
			or ($us_ping and $us_uninstall and $us_pcshutdown)
		)
}

rule XWorm_V31_Exact_Build: supplement {
	meta:
		description   = "XWorm V3.1 — exact version string match (supplement to main rule)"
		author        = "Luis Suastegui"
		date          = "2026-04-02"
		sample_sha256 = "cdde3b2650c951e774a8694208c0d151e91b40db5d21da3d790d88ebd702edec"
		confidence    = "medium"
	strings:
		$us_ver31 = "XWorm V3.1" wide

		$s_xclient = "XClient" ascii fullword

		$guid = {
			61 35 36 35 65 37 38 66 2D 37 62 33 33 2D 34 37
			30 61 2D 39 62 34 63 2D 38 30 36 63 61 34 61 35
			36 61 39 33
		}
	condition:
		uint16(0) == 0x5A4D
		and filesize < 500KB
		and $us_ver31
		and $s_xclient
		and $guid
}
