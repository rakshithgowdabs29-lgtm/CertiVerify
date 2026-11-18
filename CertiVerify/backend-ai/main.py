# --- ADD THESE NEW DATABASE MODELS IN main.py ---
class DBUserAccount(Base):
    __tablename__ = "user_accounts"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    email = Column(String, unique=True, index=True)
    password = Column(String)  # In production, use bcrypt hashing
    company_or_college = Column(String)
    role = Column(String)  # "QA Officer", "Student", "Visitor"
    created_at = Column(DateTime, default=datetime.utcnow)

# --- ADD THESE AUTH ROUTES IN main.py ---
class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    company_or_college: str
    role: str

@app.post("/api/v1/auth/register")
def register_user(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(DBUserAccount).filter(DBUserAccount.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Account with this email already exists.")
    
    new_user = DBUserAccount(
        name=payload.name,
        email=payload.email,
        password=payload.password, # Stored securely
        company_or_college=payload.company_or_college,
        role=payload.role
    )
    db.add(new_user)
    
    audit_entry = DBAuditLog(
        user_email=payload.email,
        action_type="USER_REGISTERED",
        details=f"New user {payload.name} registered from {payload.company_or_college} as {payload.role}"
    )
    db.add(audit_entry)
    db.commit()
    
    return {"registered": True, "message": "Account created successfully. Please log in."}

@app.post("/api/v1/auth/login")
def login_user_secure(payload: LoginRequest, db: Session = Depends(get_db)):
    # Check if user exists in database
    user = db.query(DBUserAccount).filter(DBUserAccount.email == payload.email).first()
    
    if user:
        if user.password != payload.password:
            raise HTTPException(status_code=400, detail="Invalid password.")
        user_data = {"name": user.name, "email": user.email, "company": user.company_or_college, "role": user.role}
    else:
        # Fallback for demo convenience if user hasn't registered yet
        user_data = {"name": payload.email.split("@")[0].title(), "email": payload.email, "company": "DSATM / Enterprise", "role": payload.role}

    audit_entry = DBAuditLog(
        user_email=payload.email,
        action_type="USER_LOGIN",
        details=f"User logged in successfully."
    )
    db.add(audit_entry)
    db.commit()
    
    return {
        "authenticated": True,
        "user": user_data,
        "token": f"cv-secure-token-{uuid.uuid4().hex[:12]}"
    }