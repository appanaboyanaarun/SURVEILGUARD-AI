import os
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import declarative_base, sessionmaker

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "uploads"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "thumbnails"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "sample_videos"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "models"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "evidence"), exist_ok=True)

DEFAULT_DB_PATH = os.path.join(DATA_DIR, "surveillance_events.db").replace("\\", "/")
DATABASE_URL = os.getenv("DATABASE_URL") or f"sqlite:///{DEFAULT_DB_PATH}"

# If SQLite, use connect_args for multithreading
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def run_migrations():
    """
    Automatic schema migration helper.
    Preserves existing development/production data and adds new columns if they do not exist.
    """
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    with engine.begin() as conn:
        # Migrate 'events' table
        if "events" in existing_tables:
            columns = [c["name"] for c in inspector.get_columns("events")]
            columns_to_add = [
                ("session_id", "VARCHAR(50)"),
                ("admin_id", "INTEGER"),
                ("admin_name", "VARCHAR(100)"),
                ("evidence_video_id", "VARCHAR(50)"),
                ("sms_status", "VARCHAR(50) DEFAULT 'NONE'"),
                ("sms_sent_at", "DATETIME"),
                ("sms_phone", "VARCHAR(50)"),
            ]
            for col_name, col_type in columns_to_add:
                if col_name not in columns:
                    try:
                        conn.execute(text(f"ALTER TABLE events ADD COLUMN {col_name} {col_type}"))
                    except Exception:
                        pass

        # Migrate 'users' table
        if "users" in existing_tables:
            columns = [c["name"] for c in inspector.get_columns("users")]
            columns_to_add = [
                ("phone_number", "VARCHAR(50)"),
                ("last_login", "DATETIME"),
            ]
            for col_name, col_type in columns_to_add:
                if col_name not in columns:
                    try:
                        conn.execute(text(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}"))
                    except Exception:
                        pass

        # Migrate 'sms_logs' table
        if "sms_logs" in existing_tables:
            columns = [c["name"] for c in inspector.get_columns("sms_logs")]
            columns_to_add = [
                ("provider_message_id", "VARCHAR(255)"),
                ("delivery_status", "VARCHAR(50)"),
                ("retry_count", "INTEGER DEFAULT 0"),
                ("is_test", "BOOLEAN DEFAULT 0"),
                ("provider_accepted_at", "DATETIME"),
                ("delivered_at", "DATETIME"),
            ]
            for col_name, col_type in columns_to_add:
                if col_name not in columns:
                    try:
                        conn.execute(text(f"ALTER TABLE sms_logs ADD COLUMN {col_name} {col_type}"))
                    except Exception:
                        pass

        # Create 'notification_recipients' table if it does not exist (legacy SMS recipients — preserved for history)
        if "notification_recipients" not in existing_tables:
            try:
                conn.execute(text("""
                    CREATE TABLE notification_recipients (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(100) NOT NULL DEFAULT 'Admin Recipient',
                        phone_number VARCHAR(50) NOT NULL UNIQUE,
                        is_active BOOLEAN DEFAULT 1,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            except Exception:
                pass

        # Migrate 'users' table — add email_address column
        if "users" in existing_tables:
            columns = [c["name"] for c in inspector.get_columns("users")]
            if "email_address" not in columns:
                try:
                    conn.execute(text("ALTER TABLE users ADD COLUMN email_address VARCHAR(255)"))
                except Exception:
                    pass

        # Create 'email_recipients' table if it does not exist
        if "email_recipients" not in existing_tables:
            try:
                conn.execute(text("""
                    CREATE TABLE email_recipients (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(100) NOT NULL DEFAULT 'Admin Recipient',
                        email_address VARCHAR(255) NOT NULL UNIQUE,
                        recipient_type VARCHAR(50) NOT NULL DEFAULT 'admin',
                        is_active BOOLEAN DEFAULT 1,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            except Exception:
                pass
        else:
            # Migrate email_recipients table
            columns = [c["name"] for c in inspector.get_columns("email_recipients")]
            if "recipient_type" not in columns:
                try:
                    conn.execute(text("ALTER TABLE email_recipients ADD COLUMN recipient_type VARCHAR(50) DEFAULT 'admin'"))
                except Exception:
                    pass

        # Create 'email_logs' table if it does not exist
        if "email_logs" not in existing_tables:
            try:
                conn.execute(text("""
                    CREATE TABLE email_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        incident_id VARCHAR(50),
                        recipient_email VARCHAR(255) NOT NULL,
                        recipient_email_masked VARCHAR(255),
                        subject VARCHAR(500) NOT NULL,
                        provider VARCHAR(50) DEFAULT 'apps_script',
                        provider_message_id VARCHAR(255),
                        status VARCHAR(50) DEFAULT 'QUEUED',
                        error_message TEXT,
                        attempt_count INTEGER DEFAULT 0,
                        is_test BOOLEAN DEFAULT 0,
                        sent_at DATETIME,
                        delivered_at DATETIME,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            except Exception:
                pass
        else:
            # Migrate email_logs table
            columns = [c["name"] for c in inspector.get_columns("email_logs")]
            if "recipient_email_masked" not in columns:
                try:
                    conn.execute(text("ALTER TABLE email_logs ADD COLUMN recipient_email_masked VARCHAR(255)"))
                except Exception:
                    pass
            if "provider_message_id" not in columns:
                try:
                    conn.execute(text("ALTER TABLE email_logs ADD COLUMN provider_message_id VARCHAR(255)"))
                except Exception:
                    pass
            if "delivered_at" not in columns:
                try:
                    conn.execute(text("ALTER TABLE email_logs ADD COLUMN delivered_at DATETIME"))
                except Exception:
                    pass


def get_db():
    """Dependency for obtaining database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
