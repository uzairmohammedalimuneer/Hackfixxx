from fastapi import FastAPI, Response, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
import uvicorn

app = FastAPI(title="HACKFIX AI Deliberately Vulnerable Test Target")

# State variable to demonstrate Retest fixing in real-time!
IS_FIXED = False


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, response: Response):
    global IS_FIXED
    is_fixed_param = request.query_params.get("fixed")
    fixed_mode = IS_FIXED or (is_fixed_param == "true")

    if fixed_mode:
        # Secure, hardened configuration
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; frame-ancestors 'none';"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Server"] = "SecureGateway"
        response.set_cookie(
            key="session_token",
            value="demo_secure_token_99999",
            secure=True,
            httponly=True,
            samesite="lax"
        )
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Hardened Test Portal</title></head>
        <body style="font-family: sans-serif; padding: 20px;">
            <h1 style="color: green;">Hardened & Protected Application</h1>
            <p>All security headers and cookie flags have been applied.</p>
            <p><a href="/about">About Us</a> | <a href="/contact">Contact</a></p>
        </body>
        </html>
        """
    else:
        # Deliberately vulnerable configuration for security demonstration
        response.headers["Server"] = "InsecureDemoServer/1.2.3"
        response.headers["X-Powered-By"] = "VulnerablePythonFramework/0.9"
        response.headers["Access-Control-Allow-Origin"] = "*"
        # Missing CSP, HSTS, X-Content-Type-Options, X-Frame-Options!
        # Insecure cookie
        response.set_cookie(
            key="session_token",
            value="demo_insecure_token_12345",
            secure=False,
            httponly=False
        )
        return """
        <!DOCTYPE html>
        <html>
        <head><title>Vulnerable Demo Portal</title></head>
        <body style="font-family: sans-serif; padding: 20px;">
            <h1 style="color: red;">Vulnerable Target Web Application</h1>
            <p>This web application is configured with deliberate security misconfigurations for HACKFIX AI auditing.</p>
            <ul>
                <li>Missing Content-Security-Policy</li>
                <li>Missing X-Content-Type-Options (nosniff)</li>
                <li>Missing Anti-Clickjacking headers</li>
                <li>Cookies missing HttpOnly and Secure flags</li>
                <li>Leaking server banner and X-Powered-By</li>
                <li>Permissive CORS wildcard</li>
            </ul>
            <p><a href="/about">About Us</a> | <a href="/contact">Contact</a> | <a href="/debug-trace">Debug Error Page</a></p>
        </body>
        </html>
        """


@app.get("/about", response_class=HTMLResponse)
async def about():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>About Demo Target</title></head>
    <body style="font-family: sans-serif; padding: 20px;">
        <h2>About Demo Website</h2>
        <p>Demonstration same-origin subpage for crawler testing.</p>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    """


@app.get("/contact", response_class=HTMLResponse)
async def contact():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Contact Demo Target</title></head>
    <body style="font-family: sans-serif; padding: 20px;">
        <h2>Contact Page</h2>
        <p>Support contact page.</p>
        <p><a href="/">Back to Home</a></p>
    </body>
    </html>
    """


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return """User-agent: *
Disallow: /secret-admin-portal/
Disallow: /database-backup/
Disallow: /internal-staging/
"""


@app.get("/.env", response_class=PlainTextResponse)
async def env_file():
    global IS_FIXED
    if IS_FIXED:
        return Response(status_code=404)
    return """DB_HOST=localhost
DB_USER=demo_root
DB_PASSWORD=secret_password_test_123
APP_SECRET_KEY=super_secret_jwt_key_98765
"""


@app.get("/debug-trace", response_class=HTMLResponse)
async def debug_trace():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>500 Internal Server Error</title></head>
    <body>
        <h1>500 Internal Server Error</h1>
        <pre>
Traceback (most recent call last):
  File "/var/www/app/main.py", line 42, in process_transaction
    user_id = auth_header['sub']
KeyError: 'sub'
        </pre>
    </body>
    </html>
    """


@app.post("/toggle-fix")
async def toggle_fix():
    global IS_FIXED
    IS_FIXED = not IS_FIXED
    return {
        "status": "success",
        "fixed_mode": IS_FIXED,
        "message": "Security headers and fixes enabled!" if IS_FIXED else "Vulnerable mode enabled!"
    }


if __name__ == "__main__":
    uvicorn.run("test_target.target_app:app", host="127.0.0.1", port=8001, reload=False)

