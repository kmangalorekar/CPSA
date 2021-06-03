(herald "5G EAP-TLS 1.3 Protocol"
	(algebra diffie-hellman))

(defprotocol eap diffie-hellman
	(defrole ue
		(vars (nonce_ue nonce_ue2 nonce_nw nonce_nw2 supi data) 				 
			(ue nw ca name)
			(x rndx)
			(h1 base)
		)
		(trace
		    (send (enc supi nonce_ue (pubk nw)))
		    (recv "Start TLS")
		    (send 
				(cat 
					"Client-Hello" 
					nonce_ue2 
					(exp (gen) x)
				)
			) ;Client Hello
		    (recv 
				(cat 
					"Server-Hello" 
					nonce_nw 
					h1 ;Server Hello

					(enc 
						nw 
						"Client-Hello" 
						nonce_ue2 
						(exp (gen) x) 
						"Server-Hello" 
						nonce_nw 
						h1 
						(exp h1 x)
					) ;Encrypted Extension

					(enc 
						nw 
						"Certificate-Request" 
						nonce_nw2 
						(enc 
							nw 
							"Client-Hello" 
							nonce_ue2 
							(exp (gen) x) 
							"Server-Hello" 
							nonce_nw 
							h1 
							(exp h1 x)
						) ;encrypted extension
						(privk ca)
					) ;Certificate Request (contains encrypted extension)

					(enc 
						nw 
						(pubk nw) 
						(privk ca)
					);Certificate

					(enc 
						(hash 
							"Client-Hello" 
							nonce_ue2 
							h1 ;client hello

							"Server-Hello" 
							nonce_nw 
							h1 ;Server Hello

							(enc 
								nw 
								"Client-Hello" 
								nonce_ue2 
								(exp (gen) x) 
								"Server-Hello" 
								nonce_nw 
								h1 
								(exp h1 x)
							) ;encrypted extension

							(enc 
								nw 
								"Certificate-Request" 
								nonce_nw2 
								(enc 
									nw 
									"Client-Hello" 
									nonce_ue2 
									(exp (gen) x) 
									"Server-Hello" 
									nonce_nw 
									h1 
									(exp h1 x)
								) ;encrypted extension

								(privk ca)
							) ;certificate request (contains encrypted extension)

							(enc 
								nw 
								(pubk nw) 
								(privk ca)
							);certificate
						) 
						(privk nw)
					) ;Certificate Verify (contains client-hello, server-hello, encrypted extension, certificate request, and certificate)

					
					(enc 
						(hash 
							(hash (exp h1 x) "Finished") ;Finish with MAC Key
							(hash 
								"Client-Hello" 
								nonce_ue2 
								h1 ;client hello

								"Server-Hello" 
								nonce_nw 
								h1 ;Server Hello

								(enc 
									nw 
									"Client-Hello" 
									nonce_ue2 
									(exp (gen) x) 
									"Server-Hello" 
									nonce_nw 
									h1 
									(exp h1 x)
								) ;Encrypted Extension

								(enc 
									nw 
									"Certificate-Request" 
									nonce_nw2 
									(enc 
										nw 
										"Client-Hello" 
										nonce_ue2 
										(exp (gen) x) 
										"Server-Hello" 
										nonce_nw 
										h1 
										(exp h1 x)
									) ;encrypted extension

									(privk ca)
								) ;Certificate Request (contains encrypted extension)

								(enc 
									nw 
									(pubk nw) 
									(privk ca)
								);Certificate

								(enc 
									(hash 
										"Client-Hello" 
										nonce_ue2 
										h1 ;client hello

										"Server-Hello" 
										nonce_nw 
										h1 ;Server Hello

										(enc 
											nw 
											"Client-Hello" 
											nonce_ue2 
											(exp (gen) x) 
											"Server-Hello" 
											nonce_nw 
											h1 
											(exp h1 x)
										) ;Encrypted Extension

										(enc 
											nw 
											"Certificate-Request" 
											nonce_nw2 
											(enc 
												nw 
												"Client-Hello" 
												nonce_ue2 
												(exp (gen) x) 
												"Server-Hello" 
												nonce_nw 
												h1 
												(exp h1 x)
											) ;Encrypted Extension

											(privk ca)
										) ;Certificate Request (contains encrypted extension)

										(enc 
											nw 
											(pubk nw) 
											(privk ca)
										);Certificate
									) 
									(privk nw)
								) ;Certificate Verify (contains client-hello, server-hello, encrypted extension, certificate request, and certificate)
							) 
						)
						(privk ca)
					) ;Finish with MAC key (contains client-hello, server-hello, encrypted extension, certificate, and certificate verify)
				)
			)
			(send 
				(cat 
					(enc 
						ue 
						(pubk ue) 
						(privk ca)
					) ;Client Certificate
					
					(enc 
						(hash 
							"Client-Hello" 
							nonce_ue2 
							h1 ;client hello

							"Server-Hello" 
							nonce_nw 
							h1 ;Server Hello

							(enc 
								nw 
								"Client-Hello" 
								nonce_ue2 
								(exp (gen) x) 
								"Server-Hello" 
								nonce_nw 
								h1 
								(exp h1 x)
							) ;Encrypted Extension

							(enc 
								nw 
								"Certificate-Request" 
								nonce_nw2 
								(enc 
									nw 
									"Client-Hello" 
									nonce_ue2 
									(exp (gen) x) 
									"Server-Hello" 
									nonce_nw 
									h1 
									(exp h1 x)
								) ;Encrypted Extension

								(privk ca)
							) ;Certificate Request (contains encrypted extension)

							(enc 
								ue 
								(pubk ue) 
								(privk ca)
							) ;Client Certificate
						)
						(privk ue)
					);Certificate Verify (contains client-hello, server-hello, encrypted extension, certificate request, and client certificate)

					;Finish with MAC key (contains client-hello, server-hello, encrypted extension, client certificate, and certificate verify)
					(enc 
						(hash 
							(hash (exp h1 x) "Finished") ;Finish with MAC Key
							(hash 
								"Client-Hello" 
								nonce_ue2 
								h1 ;client hello

								"Server-Hello" 
								nonce_nw 
								h1 ;Server Hello

								(enc 
									nw 
									"Client-Hello" 
									nonce_ue2 
									(exp (gen) x) 
									"Server-Hello" 
									nonce_nw 
									h1 
									(exp h1 x)
								) ;Encrypted Extension

								(enc 
									nw 
									"Certificate-Request" 
									nonce_nw2 
									(enc 
										nw 
										"Client-Hello" 
										nonce_ue2 
										(exp (gen) x) 
										"Server-Hello" 
										nonce_nw 
										h1 
										(exp h1 x)
									) ;Encrypted Extension

									(privk ca)
								) ;Certificate Request (contains encrypted extension)

								(enc 
									ue 
									(pubk ue) 
									(privk ca)
								) ;Client Certificate

								(enc 
									(hash 
										"Client-Hello" 
										nonce_ue2 
										h1 ;client hello

										"Server-Hello" 
										nonce_nw 
										h1 ;Server Hello

										(enc 
											nw 
											"Client-Hello" 
											nonce_ue2 
											(exp (gen) x) 
											"Server-Hello" 
											nonce_nw 
											h1 
											(exp h1 x)
										) ;Encrypted Extension

										(enc 
											nw 
											"Certificate-Request" 
											nonce_nw2 
											(enc 
												nw 
												"Client-Hello" 
												nonce_ue2 
												(exp (gen) x) 
												"Server-Hello" 
												nonce_nw 
												h1 
												(exp h1 x)
											) ;Encrypted Extension

											(privk ca)
										) ;Certificate Request (contains encrypted extension)

										(enc 
											ue 
											(pubk ue) 
											(privk ca)
										) ;Client Certificate
									)
									(privk ue)
								);Certificate Verify (contains client-hello, server-hello, encrypted extension, certificate request, and client certificate)
							)
						)
						(privk ca)
					) ;client certificate
				)
			)
		)
		(uniq-gen x)
		(non-orig (privk ca))
	)
	
	(defrole nw
		(vars (nonce_ue nonce_ue2 nonce_nw nonce_nw2 supi data) 
			(ue nw ca name)
			(y rndx)
			(h2 base)
		)
		(trace
			(recv 
				(enc 
					supi 
					nonce_ue 
					(pubk nw)
				)
			)
		    (send "tls_start")
		    (recv 
				(cat 
					"Client-Hello" 
					nonce_ue2 
					h2
				)
			) ;Client Hello
		    (send 
				(cat 
					"Server-Hello" 
					nonce_nw 
					(exp (gen) y) ;Server Hello

					(enc 
						nw 
						"Client-Hello" 
						nonce_ue2 
						h2 
						"Server-Hello" 
						nonce_nw 
						(exp (gen) y) 
						(exp h2 y)
					) ;Encrypted Extension

					(enc 
						nw 
						"Certificate-Request" 
						nonce_nw2 
						(enc 
							nw 
							"Client-Hello" 
							nonce_ue2 
							h2 
							"Server-Hello" 
							nonce_nw 
							(exp (gen) y) 
							(exp h2 y)
						);encrypted extension
						(privk ca)
					);Certificate Request (contains encrypted extension)

					(enc 
						nw 
						(pubk nw) 
						(privk ca)
					);Certificate

					(enc 
						(hash 
							
							"Client-Hello" 
							nonce_ue2 
							h2 ;Client hello

							"Server-Hello" 
							nonce_nw 
							(exp (gen) y) ;Server Hello

							(enc 
								nw 
								"Client-Hello" 
								nonce_ue2 
								h2 
								"Server-Hello" 
								nonce_nw 
								(exp (gen) y) 
								(exp h2 y)
							) ;encrypted extension

							(enc 
								nw 
								"Certificate-Request" 
								nonce_nw2 
								(enc 
									nw 
									"Client-Hello" 
									nonce_ue2 
									h2 
									"Server-Hello" 
									nonce_nw 
									(exp (gen) y) 
									(exp h2 y)
								);encrypted extension
								(privk ca)
							);certificate request (contains encrypted extension)

							(enc 
								nw 
								(pubk nw) 
								(privk ca)
							);certificate
						) 
						(privk nw)
					) ;Certificate Verify (contains client-hello, server-hello, encrypted extension, certificate request, and certificate)

					(enc 
						(hash 
							(hash (exp h2 y) "Finished") 
							(hash 
								"Client-Hello" 
								nonce_ue2 
								h2 ;Client hello

								"Server-Hello" 
								nonce_nw 
								(exp (gen) y) ;Server Hello

								(enc 
									nw 
									"Client-Hello" 
									nonce_ue2 
									h2 
									"Server-Hello" 
									nonce_nw 
									(exp (gen) y) 
									(exp h2 y)
								) ;Encrypted Extension

								(enc 
									nw 
									"Certificate-Request" 
									nonce_nw2 
									(enc 
										nw 
										"Client-Hello" 
										nonce_ue2 
										h2 
										"Server-Hello" 
										nonce_nw 
										(exp (gen) y) 
										(exp h2 y)
									);encrypted extension
									(privk ca)
								);Certificate Request (contains encrypted extension)

								(enc 
									nw 
									(pubk nw) 
									(privk ca)
								);Certificate

								(enc 
									(hash 
										
										"Client-Hello" 
										nonce_ue2 
										h2 ;Client hello

										"Server-Hello" 
										nonce_nw 
										(exp (gen) y) ;Server Hello

										(enc 
											nw 
											"Client-Hello" 
											nonce_ue2 
											h2 
											"Server-Hello" 
											nonce_nw 
											(exp (gen) y) 
											(exp h2 y)
										) ;encrypted extension

										(enc 
											nw 
											"Certificate-Request" 
											nonce_nw2 
											(enc 
												nw 
												"Client-Hello" 
												nonce_ue2 
												h2 
												"Server-Hello" 
												nonce_nw 
												(exp (gen) y) 
												(exp h2 y)
											);encrypted extension
											(privk ca)
										);certificate request (contains encrypted extension)

										(enc 
											nw 
											(pubk nw) 
											(privk ca)
										);certificate
									) 
									(privk nw)
								) ;Certificate Verify (contains client-hello, server-hello, encrypted extension, certificate request, and certificate)
							)
						)
						(privk ca)
					) ;Finish with MAC (contains client-hello, server-hello, encrypted extension, certificate, and certificate verify)
				)
			)

			(recv 
				(cat 
					(enc 
						ue 
						(pubk ue) 
						(privk ca)
					) ;client certificate

					(enc 
						(hash 
							"Client-Hello" 
							nonce_ue2 
							h2 ;Client hello

							"Server-Hello" 
							nonce_nw 
							(exp (gen) y) ;Server Hello

							(enc 
								nw 
								"Client-Hello" 
								nonce_ue2 
								h2 
								"Server-Hello" 
								nonce_nw 
								(exp (gen) y) 
								(exp h2 y)
							) ;Encrypted Extension

							(enc 
								nw 
								"Certificate-Request" 
								nonce_nw2 
								(enc 
									nw 
									"Client-Hello" 
									nonce_ue2 
									h2 
									"Server-Hello" 
									nonce_nw 
									(exp (gen) y) 
									(exp h2 y)
								);encrypted extension
								(privk ca)
							);Certificate Request (contains encrypted extension)

							(enc 
								ue 
								(pubk ue) 
								(privk ca)
							) ;Client Certificate			
						) 
						(privk ue)
					) ;Certificate Verify (contains client-hello, server-hello, encrypted extension, certificate request, and client certificate)

					(enc 
						(hash 
							(hash (exp h2 y) "Finished") ;Finish with MAC Key
							(hash 
								"Client-Hello" 
								nonce_ue2 
								h2 ;Client hello

								"Server-Hello" 
								nonce_nw 
								(exp (gen) y) ;Server Hello

								(enc 
									nw 
									"Client-Hello" 
									nonce_ue2 
									h2 
									"Server-Hello" 
									nonce_nw 
									(exp (gen) y) 
									(exp h2 y)
								) ;Encrypted Extension

								(enc 
									nw 
									"Certificate-Request" 
									nonce_nw2 
									(enc 
										nw 
										"Client-Hello" 
										nonce_ue2 
										h2 
										"Server-Hello" 
										nonce_nw 
										(exp (gen) y) 
										(exp h2 y)
									);encrypted extension
									(privk ca)
								);Certificate Request (contains encrypted extension)

								(enc 
									ue 
									(pubk ue) 
									(privk ca)
								) ;Client Certificate	

								(enc 
									(hash 
										"Client-Hello" 
										nonce_ue2 
										h2 ;Client hello

										"Server-Hello" 
										nonce_nw 
										(exp (gen) y) ;Server Hello

										(enc 
											nw 
											"Client-Hello" 
											nonce_ue2 
											h2 
											"Server-Hello" 
											nonce_nw 
											(exp (gen) y) 
											(exp h2 y)
										) ;Encrypted Extension

										(enc 
											nw 
											"Certificate-Request" 
											nonce_nw2 
											(enc 
												nw 
												"Client-Hello" 
												nonce_ue2 
												h2 
												"Server-Hello" 
												nonce_nw 
												(exp (gen) y) 
												(exp h2 y)
											);encrypted extension
											(privk ca)
										);Certificate Request (contains encrypted extension)

										(enc 
											ue 
											(pubk ue) 
											(privk ca)
										) ;Client Certificate			
									) 
									(privk ue)
								) ;Certificate Verify (contains client-hello, server-hello, encrypted extension, certificate request, and client certificate)
							) 
						)
						(privk ca)
					);Finish with MAC key (contains client-hello, server-hello, encrypted extension, client certificate, and certificate verify)
				)
			)
		)
		(uniq-gen y)
		(non-orig (privk ca))
	)
)

;;; UE point of view.
(defskeleton eap
	    (vars (nonce_ue nonce_ue2 nonce_nw nonce_nw2 supi data) 
			(ue nw ca name)
			(x rndx)
			(h1 base)
		)
		(defstrandmax ue 
			(nonce_ue nonce_ue) (nonce_ue2 nonce_ue2) (nonce_nw nonce_nw) (nonce_nw2 nonce_nw2) (supi supi) (ue ue) (nw nw) (ca ca) (x x) (h1 h1)
		)
		(uniq-orig nonce_ue)
		(uniq-orig nonce_ue2)
		(non-orig (privk ue))
		(non-orig (privk nw))
)


;;; NW point of view.
(defskeleton eap
	    (vars (nonce_ue nonce_ue2 nonce_ue3 nonce_nw nonce_nw2 supi data) 
			(ue nw ca name)
			(y rndx)
			(h2 base)
		)
	    (defstrandmax nw 
			(nonce_ue nonce_ue) (nonce_ue2 nonce_ue2) (nonce_nw nonce_nw) (nonce_nw2 nonce_nw2) (supi supi) (ue ue) (nw nw) (ca ca) (y y) (h2 h2)
		)
		(uniq-orig nonce_nw)
		(uniq-orig nonce_nw2)
	    (non-orig (privk nw))
		(non-orig (privk ue))
)
