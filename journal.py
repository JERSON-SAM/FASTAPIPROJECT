from fastapi import FastAPI, HTTPException, Depends, Form
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import pymysql.cursors
import bcrypt

app = FastAPI(title="Daily Journal API")

# Database connection function
def get_db():
    connection = pymysql.connect(
        host="localhost",
        user="root",
        password="",
        database="daily_journal",
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        yield connection
    finally:
        connection.close()

# Pydantic models for validation
class JournalEntry(BaseModel):
    title: str
    content: str
    date: str
    user_id: int

class JournalEntryUpdate(BaseModel):
    title: str
    content: str
    date: str

class User(BaseModel):
    username: str
    email: str
    password: str

class UserUpdate(BaseModel):
    username: str
    email: str

# 1. Register a new user
@app.post("/users/")
async def register_user(user: User, db=Depends(get_db)):
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    with db.cursor() as cursor:
        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                       (user.username, user.email, hashed_password))
        db.commit()
        user_id = cursor.lastrowid
    return {"message": "User created", "user_id": user_id}

# 2. Get all users
@app.get("/users/")
async def get_users(db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
    return users or "No users found"

# 3. Get a specific user by ID
@app.get("/users/{user_id}")
async def get_user(user_id: int, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
    return user

# 4. Update user details
@app.put("/users/{user_id}")
async def update_user(user_id: int, user: UserUpdate, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        existing_user = cursor.fetchone()
        if not existing_user:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute("UPDATE users SET username = %s, email = %s WHERE user_id = %s",
                       (user.username, user.email, user_id))
        db.commit()
    return {"message": "User updated"}

# 5. Delete a user
@app.delete("/users/{user_id}")
async def delete_user(user_id: int, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        db.commit()
    return {"message": "User deleted"}

# 6. Add a new journal entry associated with a user
@app.post("/entries/")
async def add_entry(entry: JournalEntry, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (entry.user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        cursor.execute("INSERT INTO journal_entries (title, content, date, user_id) VALUES (%s, %s, %s, %s)",
                       (entry.title, entry.content, entry.date, entry.user_id))
        db.commit()
        entry_id = cursor.lastrowid
    return RedirectResponse(url=f"/entries/{entry_id}")

# 7. Get all journal entries, optionally filtering by user
@app.get("/entries/")
async def get_entries(user_id: int = None, db=Depends(get_db)):
    with db.cursor() as cursor:
        if user_id:
            cursor.execute("SELECT * FROM journal_entries WHERE user_id = %s", (user_id,))
        else:
            cursor.execute("SELECT * FROM journal_entries")
        entries = cursor.fetchall()
    return entries or "No entries found"

# 8. Update a journal entry
@app.put("/entries/{entry_id}")
async def update_entry(entry_id: int, entry: JournalEntryUpdate, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM journal_entries WHERE id = %s", (entry_id,))
        existing_entry = cursor.fetchone()
        if not existing_entry:
            raise HTTPException(status_code=404, detail="Entry not found")

        cursor.execute("UPDATE journal_entries SET title = %s, content = %s, date = %s WHERE id = %s",
                       (entry.title, entry.content, entry.date, entry_id))
        db.commit()
    return RedirectResponse(url=f"/entries/{entry_id}")

# 9. Delete a journal entry
@app.delete("/entries/{entry_id}")
async def delete_entry(entry_id: int, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM journal_entries WHERE id = %s", (entry_id,))
        entry = cursor.fetchone()
        if not entry:
            raise HTTPException(status_code=404, detail="Entry not found")

        cursor.execute("DELETE FROM journal_entries WHERE id = %s", (entry_id,))
        db.commit()
    return RedirectResponse(url="/entries/")

# 10. Get a specific journal entry by ID
@app.get("/entries/{entry_id}")
async def get_entry(entry_id: int, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM journal_entries WHERE id = %s", (entry_id,))
        entry = cursor.fetchone()
        if not entry:
            raise HTTPException(status_code=404, detail="Entry not found")
    return entry

# 11. Search journal entries by title
@app.get("/entries/search")
async def search_entries_by_title(title: str, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM journal_entries WHERE title LIKE %s", ('%' + title + '%',))
        entries = cursor.fetchall()
    return entries or "No entries found"

# 12. Get entries by user ID
@app.get("/users/{user_id}/entries")
async def get_user_entries(user_id: int, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM journal_entries WHERE user_id = %s", (user_id,))
        entries = cursor.fetchall()
    return entries or "No entries found"

# 13. Login user
@app.post("/login/")
async def login(username: str = Form(...), password: str = Form(...), db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            raise HTTPException(status_code=401, detail="Invalid credentials")
    # For demonstration purposes, we're not generating a session token here.
    return {"message": "Login successful"}

# 14. Logout user (for demonstration purposes; typically requires session handling)
@app.post("/logout/")
async def logout():
    # Handle logout logic (e.g., invalidate token or session)
    return {"message": "Logged out"}

# 15. Reset user password (requires additional security measures)
@app.post("/users/{user_id}/reset_password/")
async def reset_password(user_id: int, new_password: str, db=Depends(get_db)):
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        cursor.execute("UPDATE users SET password = %s WHERE user_id = %s",
                       (hashed_password, user_id))
        db.commit()
    return {"message": "Password reset successfully"}

# 16. Get user profile information
@app.get("/users/{user_id}/profile")
async def get_user_profile(user_id: int, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT username, email FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
    return user

# 17. Update user profile information
@app.put("/users/{user_id}/profile")
async def update_user_profile(user_id: int, user: UserUpdate, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        existing_user = cursor.fetchone()
        if not existing_user:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute("UPDATE users SET username = %s, email = %s WHERE user_id = %s",
                       (user.username, user.email, user_id))
        db.commit()
    return {"message": "User profile updated"}

# 18. Get all journal entries for a specific user
@app.get("/entries/user/{user_id}")
async def get_all_entries_for_user(user_id: int, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM journal_entries WHERE user_id = %s", (user_id,))
        entries = cursor.fetchall()
    return entries or "No entries found"

# 19. Get journal entries count for a specific user
@app.get("/entries/user/{user_id}/count")
async def get_entries_count_for_user(user_id: int, db=Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM journal_entries WHERE user_id = %s", (user_id,))
        count = cursor.fetchone()['COUNT(*)']
    return {"entries_count": count}

# 20. Get user login status (for demonstration purposes)
@app.get("/status/")
async def get_status():
    # This would typically involve checking a session or token.
    return {"status": "Service is running"}
