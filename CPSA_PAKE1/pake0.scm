;; This is a minimal template for a CPSA input file.

;; Replace <TITLE> with the desired title and <PROTONAME>
;; with the desired name of your project.

;; The defrole template below may be copied and used as
;; a starting point for the roles of your protocol.
;; Change the <ROLENAME> field in each copy as desired.
;; Roles must have distinct names.

;; The basic cryptoalgebra is selected by default. If
;; your project requires the diffie-hellman algebra,
;; delete "basic" on the defprotocol line, uncomment
;; "diffie-hellman" on this same line and uncomment
;; the "(algebra diffie-hellman)" statement in the
;; herald.

;; Refer to the CPSA manual for more information
;; about syntax and additional features.

(herald "Pake"
	;; (algebra diffie-hellman)
	)

(defprotocol Pake  basic ;; diffie-hellman
  (defrole fourth
    (vars (t f name) (pk skey) (Nt Nf data))
    (trace
   	(send (enc Nf f (pubk t))) 
	(recv (enc Nf Nt t (pubk f)))
	(send (enc Nt (pubk t)))
    
    	(send (enc (enc pk (hash Nf Nt)) (pubk t)))
    )
	(uniq-orig pk)
    )


 (defrole third
    (vars (t f name) (pk skey) (Nt Nf data))
    (trace
   	(recv (enc Nf f (pubk t)))
	(send (enc Nf Nt t (pubk f)))
	(recv (enc Nt (pubk t)))
	;;(recv (enc pk (hash Nf Nt)))
	
    	(recv (enc (enc pk (hash Nf Nt)) (pubk t)))
    (init pk)
    
    )
    )


  (defrole alice
    (vars (a b name) (pk skey) (Na Nb data))
    (trace
    	;;(send (enc pk pk) )
	(obsv pk)

	
      (send Na)
      (recv Nb)
      ;;(send
;;	(hash (hash pk a b Na Nb))
;;	)
	(send (hash (hash pk a b Na Nb)))

      (recv
	 (hash  (hash(hash pk a b Na Nb))  (hash pk a b Na Nb))
	
	))
	;;(uniq-orig pk)
    )

  (defrole bob
    (vars (a b name) (pk skey) (Na Nb data))
    (trace

	(obsv pk)
      (recv Na)
      (send Nb)
      (recv
	(hash (hash pk a b Na Nb))
	)

      (send
	 (hash  (hash (hash pk a b Na Nb))  (hash pk a b Na Nb))
	
	)
     )
    )

  )

(defskeleton Pake
  (vars (a b name) (Na Nb data))
  (defstrandmax alice (a a) (b b) (Na Na) (Nb Nb) )
  (uniq-orig Na)
  )



(defskeleton Pake
  (vars (a b name) (Na Nb data))
  (defstrandmax bob (a a) (b b) (Na Na) (Nb Nb) )
  (uniq-orig Nb)
  )



(defskeleton Pake
  (vars (t f name) (Nt Nf data))
  (defstrandmax third (t t) (f f) (Nt Nt) (Nf Nf) )
  (uniq-orig Nt)
  (non-orig (privk t) (privk f))
  )



(defskeleton Pake
  (vars (t f name) (Nt Nf data))
  (defstrandmax fourth (t t) (f f) (Nt Nt) (Nf Nf) )
  (uniq-orig Nf)
  (non-orig (privk t) (privk f))
  )


