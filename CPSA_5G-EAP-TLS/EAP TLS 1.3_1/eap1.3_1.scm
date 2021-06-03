(herald "5G EAP-TLS Protocol"
	(comment "5G-EAP-TLS Protocol using TLS ver 1.2")
	(reverse-nodes)
	(bound 20)
	(limit 8000)
    (algebra diffie-hellman)
)
	
	
(defprotocol eap diffie-hellman
	(defrole UE
		(vars (ue ausf name) (SUPI data) (x rndx) (rue mue nue nausf data) (Certificate name) (as akey) (h2 base))
		(trace
			(send 
				(enc SUPI rue (pubk ausf))
			)
			(recv 
				(enc "TLS-START" (pubk ue))
			)
			(send
				(cat 
					"ClientHello"
					(exp (gen) x) 
					mue
				)
			)
			(recv
				(cat 
					"ServerHello"
					h2
					(enc
						(enc ausf as (privk Certificate))
						(enc
							(hash 
								(exp (gen) x)
								mue
							)
							(invk as)
						)
						(exp h2 x)
					)
				)
			)
			(send
				(enc nue (exp h2 x))
			)
			(recv
				(enc nue nausf (exp h2 x))
			)
			(send
				(enc "EAP-TLS" (exp h2 x))
			)
			(recv 
				(enc "Success" (exp h2 x))
			)
		)
		(non-orig (privk Certificate))
		(uniq-orig rue mue nue)
		(uniq-gen x)
	)

	(defrole AUSF
		(vars (ue ausf name) (SUPI data) (y rndx) (rue mue nue nausf data) (Certificate name) (as akey) (h1 base))
		(trace
			(recv
				(cat
					(enc SUPI rue (pubk ausf))
				)
			)
			(send 
				(enc "TLS-START" (pubk ue))
			)
			(recv
				(cat 
					"ClientHello"
					h1 
					mue
				)
			)
			(send
				(cat 
					"ServerHello"
					(exp (gen) y) 
					(enc
						(enc ausf as (privk Certificate))
						(enc
							(hash 
								h1
								mue
							)
							(invk as)
						)
						(exp h1 y)
					)
				)
			)
			(recv
				(enc nue (exp h1 y))
			)
			(send
				(enc nue nausf (exp h1 y))
			)
			(recv
				(enc "EAP-TLS" (exp h1 y))
			)
			(send 
				(enc "Success" (exp h1 y))
			)	
		)
		(non-orig (privk Certificate))
		(uniq-orig nausf)
		(uniq-gen y)
	)
)

(defskeleton eap
	(vars (uue aausf name) (supi data) (rrue mmue nnue nnausf data) (cert name))
	(defstrandmax UE
		(ue uue) (ausf aausf) (SUPI supi) (rue rrue) (mue mmue) (nue nnue) (nausf nnausf) (Certificate cert)
	)
	(non-orig (privk cert) (privk aausf) (privk uue))
)

(defskeleton eap
	(vars (uue aausf name) (supi data) (rrue mmue nnue nnausf data) (cert name))
	(defstrandmax AUSF
		(ue uue) (ausf aausf) (SUPI supi) (mue mmue) (nue nnue) (nausf nnausf) (Certificate cert)
	)
	(non-orig (privk cert) (privk aausf) (privk uue))
)