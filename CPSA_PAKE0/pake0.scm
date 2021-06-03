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

  (defrole alice
    (vars (a b name) (pk skey) (Na Nb data))
    (trace

      (send Na)
      (recv Nb)
      (send
	(hash (hash pk a b Na Nb))
	)

      (recv
	 (hash  (hash(hash pk a b Na Nb))  (hash pk a b Na Nb))
	
	)
     )
    )

  (defrole bob
    (vars (a b name) (pk skey) (Na Nb data))
    (trace

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
  (vars (a b name) (pk skey) (Na Nb data))
  (defstrandmax alice (a a) (b b) (Na Na) (Nb Nb) (pk pk) )

  (uniq-orig Na)
  (pen-non-orig pk)

  )



(defskeleton Pake
  (vars (a b name) (pk skey) (Na Nb data))
  (defstrandmax bob (a a) (b b) (Na Na) (Nb Nb) (pk pk) )
  (uniq-orig Nb)
  (pen-non-orig pk)

  )


(defskeleton Pake
  (vars (a b name) (pk skey) (Na Nb data))
  (defstrandmax alice (a a) (b b) (Na Na) (Nb Nb) (pk pk) )
  (uniq-orig Na)
  )

(defskeleton Pake
  (vars (a b name) (pk skey) (Na Nb data))
  (defstrandmax bob (a a) (b b) (Na Na) (Nb Nb) (pk pk) )
  (uniq-orig Nb)
  )



