from datetime import datetime, timezone


def check_session(session, page):
    try:
        username = session.get("username")
        role = session.get("role")
        expiry = session.get("expiry")
        page_access = session.get("page_access", [])

        if not username or not role or not expiry:
            return "Unauthorized access!"

        if datetime.now(timezone.utc).timestamp() > expiry:
            session.clear()
            return "Session expired. Please log in again."

        if role not in ["admin", "developer", "qa"]:
            session.clear()
            return "Unauthorized access."

        if page not in page_access:
            return "Unauthorized page access."

        return True

    except Exception:
        return "Unknown error occurred!"
