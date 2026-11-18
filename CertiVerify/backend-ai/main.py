@app.post("/api/v1/auth/login")
def login_user_secure(payload: LoginRequest, db: Session = Depends(get_db)):
    # 1. Query PostgreSQL to check if the account exists
    user = db.query(DBUserAccount).filter(DBUserAccount.email == payload.email).first()
    
    # 2. Strict validation: Reject if user does not exist
    if not user:
        raise HTTPException(
            status_code=401, 
            detail="Account not found. Please register an account first."
        )
    
    # 3. Strict validation: Check password
    if user.password != payload.password:
        raise HTTPException(
            status_code=401, 
            detail="Invalid password. Please check your credentials."
        )

    # 4. Log successful authentication in FDA audit trail
    audit_entry = DBAuditLog(
        user_email=payload.email,
        action_type="USER_LOGIN_SUCCESS",
        details=f"User {user.name} logged in successfully."
    )
    db.add(audit_entry)
    db.commit()
    
    return {
        "authenticated": True,
        "user": {
            "name": user.name, 
            "email": user.email, 
            "company": user.company_or_college, 
            "role": user.role
        },
        "token": f"cv-secure-token-{uuid.uuid4().hex[:12]}"
    }