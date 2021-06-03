(herald "5G EAP-TLS Protocol"
	(comment "5G-EAP-TLS Protocol using TLS ver 1.2")
	(reverse-nodes)
	(bound 20)
	(limit 8000)
)
	
	
(defprotocol eap basic
	(defrole UE
		(vars (ue ausf name) (SUPI data) (rue rue1 rausf prekey data) (Certificate name))
		(trace
			(send 
				(enc SUPI rue (pubk ausf))
			)
			(recv 
				"TLS-START"
			)
			(send
				(cat rue1 "Methods_UE")
			)
			(recv
				(cat 
					rausf 
					(enc ausf (pubk ausf) (privk Certificate))
					"Methods_AUSF"
				)
			)
			(send
				(cat
					(enc prekey (pubk ausf))
					(enc ue (pubk ue) (privk Certificate))
					(enc
						(hash 
							"TLS-START" 
							rue1
							"Methods_UE"
							rausf 
							(enc ausf (pubk ausf) (privk Certificate))
							"Methods_AUSF"
						)
						(hash rue1 prekey rausf)
					)
				)
			)
			(recv
				(enc
					(hash 
						"TLS-START" 
						rue1
						"Methods_UE"
						rausf 
						(enc ausf (pubk ausf) (privk Certificate))
						"Methods_AUSF"
                        (enc prekey (pubk ausf))
                        (enc ue (pubk ue) (privk Certificate))
					)
					(hash rue1 prekey rausf)
				)
			)
			(send
				(enc
                    "EAP-TLS"
                    (hash rue1 prekey rausf)
                )
			)
			(recv
				(enc
					"Success"
                    (hash rue1 prekey rausf)
				)
			)
		)
		(non-orig (privk Certificate))
	)
	(defrole AUSF
		(vars (ue ausf name) (SUPI data) (rue rue1 rausf prekey data) (Certificate name))
		(trace
			(recv
				(cat
					(enc SUPI rue (pubk ausf))
				)
			)
			(send 
				"TLS-START"
			)
			(recv
				(cat rue1 "Methods_UE")
			)
			(send
				(cat 
					rausf 
					(enc ausf (pubk ausf) (privk Certificate))
					"Methods_AUSF"
				)
			)
			(recv
				(cat
					(enc prekey (pubk ausf))
					(enc ue (pubk ue) (privk Certificate))
					(enc
						(hash 
							"TLS-START" 
							rue1
							"Methods_UE"
							rausf 
							(enc ausf (pubk ausf) (privk Certificate))
							"Methods_AUSF"
						)
						(hash rue1 prekey rausf)
					)
				)
			)
			(send
				(enc
					(hash 
						"TLS-START" 
						rue1
						"Methods_UE"
						rausf 
						(enc ausf (pubk ausf) (privk Certificate))
						"Methods_AUSF"
                        (enc prekey (pubk ausf))
                        (enc ue (pubk ue) (privk Certificate))
                    )
					(hash rue1 prekey rausf)
				)
			)
			(recv
				(enc
                    "EAP-TLS"
                    (hash rue1 prekey rausf)
                )
			)
			(send
				(enc
                    "Success"
                   (hash rue1 prekey rausf) 
                )
			)	
		)
		(non-orig (privk Certificate))
	)
)

(defskeleton eap
	(vars (uue aausf name) (supi data) (rrue rrue1 rprekey data) (cert name))
	(defstrandmax UE
		(ue uue) (ausf aausf) (SUPI supi) (rue rrue) (rue1 rrue1) (prekey rprekey) (Certificate cert)
	)
	(uniq-orig rrue)
	(uniq-orig rrue1)
	(uniq-orig rprekey)
	(non-orig (privk cert) (privk uue) (privk aausf))
)

(defskeleton eap
	(vars (uue aausf name) (supi data) ( rrausf rprekey data) (cert name))
	(defstrandmax AUSF
		(ue uue) (ausf aausf) (SUPI supi) (rausf rrausf) (prekey rprekey) (Certificate cert)
	)
	(uniq-orig rrausf)
	(non-orig (privk cert) (privk uue) (privk aausf))
)