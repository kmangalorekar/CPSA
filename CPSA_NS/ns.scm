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

(herald "Needham Schroder"
	;; (algebra diffie-hellman)
	)

(defprotocol ns basic ;; diffie-hellman

  (defrole alice
    (vars (a b name) (Na Nb data))
    (trace
	(send
	  (enc Na a (pubk b))
	 )

	(recv
		(enc Na Nb  (pubk a))  
	  
	)
	 
	(send
		(enc Nb  (pubk b))
	 )


     )
    )
  (defrole bob
    (vars (a b name) (Na Nb data))
    (trace
      (recv
	  (enc Na a (pubk b))
	 )

	(send
		(enc Na Nb  (pubk a))  
	  
	)
	 
	(recv
		(enc Nb  (pubk b))
	 )

     )
    )


  )

(defskeleton ns
  (vars (a b name) (Na Nb data))
  (defstrandmax alice (a a) (b b) (Na Na) (Nb Nb) )
  (uniq-orig Na)
  (non-orig (privk a) (privk b))
  )

(defskeleton ns
  (vars (a b name) (Na Nb data))
  (defstrandmax bob (a a) (b b) (Na Na) (Nb Nb) )
  (uniq-orig Nb)
  (non-orig (privk a) (privk b))
  )

