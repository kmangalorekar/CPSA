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

(herald "SRP3 Protocol"
	(algebra diffie-hellman)
	(limit 8000)
	(bound 40)
	)

(defprotocol srp  diffie-hellman

  (defrole client-init
    (vars (cl sr name) (s data) (x rndx))
    (trace
	(init (cat "Client state" s x cl sr))
	(init (cat "Enroll" s (exp (gen) x)))
     )
     (uniq-gen x)
    
    )

  (defrole server-init
    (vars (cl sr name) (s data) (x rndx) (v base))
    (trace
	(obsv (cat "Enroll" s v))
	(init (cat "Server Record" s v cl sr))
     )

    )

  (defrole client
    (vars (cl sr name) (s data) (x a u rndx) (v bb base))
    (trace
	(send cl)
	(recv s)
	(obsv (cat "Client state" s x cl sr))
	(send (exp (gen) a))
	(recv (cat (enc bb v) u))

	(send 
	
		(hash
	    		(exp (gen) a) ;;g^a
	    		(enc bb v) ;;v+g^(b)
	    		(hash (hash (exp bb a) (exp bb (mul u x))))
	
	  	)
	)


	(recv 	
	
		(hash
			(exp (gen) a)

			(hash (exp (gen) a) (enc bb v) (hash (hash (exp bb a) (exp bb (mul u x)))))
	
		 	(hash (hash (exp bb a) (exp bb (mul u x))))

		)
	)

     )
     (uniq-gen a)


    )

  (defrole server
    (vars (cl sr name) (s data) (x b u rndx) (v ba base) )
    (trace
	(recv cl)
	(obsv (cat "Server Record" s v cl sr))
	(send s)
	(recv ba)
	(send (cat (enc (exp (gen) b) v) u))

	(recv
	
		(hash
	    		ba ;;g^a
	    		(enc (exp (gen) b) v) ;;v+g^(b)
	    		(hash (hash (exp ba b) (exp (exp (gen) b) (mul u x))))
	
	  	)
	)


	(send 
		(hash 
			ba
			(hash ba (enc (exp (gen) b) v) (hash (hash (exp ba b) (exp (exp (gen) b) (mul u x)))))
	
			(hash (hash (exp ba b) (exp (exp (gen) b) (mul u x)))) 
		)
	
	)
    
    
    )
	(uniq-gen b)	



	)



)






(defskeleton srp
  (vars (cl sr name) (s data))
  (defstrandmax client-init (cl cl) (sr sr) (s s))
  )

 (defskeleton srp
  (vars (cl sr name) (s data))
  (defstrandmax server-init (cl cl) (sr sr) (s s))
  )

  (defskeleton srp
  (vars (cl sr name) (s data) (u rndx))
  (defstrandmax client (cl cl) (sr sr) (s s) (u u))
  )

 (defskeleton srp
  (vars (cl sr name) (s data)(u rndx))
  (defstrandmax server (cl cl) (sr sr) (s s) (u u))
 (uniq-orig u)
 )


