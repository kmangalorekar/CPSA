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

(herald "Diffie Hellman Protocol"
	 (algebra diffie-hellman)
	)


;; rnd - random exponent
;; base - the product of a previous exponentiation or generator

(defprotocol dh diffie-hellman

  (defrole alice
    (vars (a b name) (ra rndx) (bb base) (n text) (pw skey))
   (trace

     (send (exp (gen) ra)) ;;send g^a
     (recv bb)
     ;;(send (enc  n (exp bb ra)))
	(send (enc n (hash pw a b (exp (gen) ra) bb (exp bb ra))))
	(recv n)
     )
   	(uniq-gen ra)
    )

  (defrole bob
    (vars (a b name)(rb rndx) (ba base) (n text) (pw skey))
    (trace

     (recv ba)
     (send (exp (gen) rb)) ;; send g^b
     ;;(recv (enc n (exp ba rb)))	
     (recv (enc n (hash pw a b ba (exp (gen) rb) (exp ba rb)) ))

     (send n)
     )
    (uniq-gen rb)
    )
  )

(defskeleton dh
  (vars (a b name) (pw skey) (n text))
  (defstrandmax alice (a a) (b b) (pw pw) (n n))
  (pen-non-orig pw)
  (uniq-orig n)
  )


(defskeleton dh
  (vars (a b name) (pw skey))
  (defstrandmax bob (a a) (b b) (pw pw))
  (pen-non-orig pw)
  )
