"""RedPulse - Context-Aware Remediation Snippets.

Generates language-specific code fixes based on tech stack for common vulns.
Deterministic, no AI generation - curated snippets per vuln+stack.
"""

from typing import Dict

_SNIPPETS: Dict[str, Dict[str, str]] = {
    "sqli": {
        "python-fastapi": """# Fix SQLi in FastAPI - use SQLAlchemy parameterized queries
from sqlalchemy import text
# BAD: f\"SELECT * FROM users WHERE id = {user_input}\"
# GOOD:
result = await db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_input})""",
        "python-django": """# Fix SQLi in Django - use ORM
# BAD: User.objects.raw(f\"SELECT * FROM users WHERE id = {user_id}\")
# GOOD:
User.objects.filter(id=user_id).first()
# Or with raw: User.objects.raw(\"SELECT * FROM users WHERE id = %s\", [user_id])""",
        "nodejs-express": """// Fix SQLi in Express - use parameterized queries (pg)
# BAD: client.query(`SELECT * FROM users WHERE id = ${req.query.id}`)
# GOOD:
await pool.query('SELECT * FROM users WHERE id = $1', [req.query.id]);""",
        "php": """// Fix SQLi in PHP - use PDO prepared statements
// BAD: $pdo->query(\"SELECT * FROM users WHERE id = $id\")
// GOOD:
$stmt = $pdo->prepare(\"SELECT * FROM users WHERE id = :id\");
$stmt->execute(['id' => $id]);""",
    },
    "xss": {
        "python-fastapi": """# Fix XSS in FastAPI - escape output with Jinja2
from markupsafe import escape
# In template: {{ user_input|e }}
# In JSON response: ensure Content-Type is application/json and escape
return {\"data\": escape(user_input)}""",
        "python-django": """# Fix XSS in Django - auto-escape templates
# In template: {{ user_input }}  (auto-escaped)
# For mark_safe, avoid unless sanitized:
from django.utils.html import escape
safe = escape(user_input)""",
        "nodejs-express": """// Fix XSS in Express - escape with he library
const he = require('he');
// BAD: res.send('<div>' + req.query.q + '</div>')
// GOOD:
res.send('<div>' + he.encode(req.query.q) + '</div>');
// Or use templating auto-escape: res.render('view', {q: req.query.q})""",
        "php": """// Fix XSS in PHP - use htmlspecialchars
// BAD: echo $_GET['q'];
// GOOD:
echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');""",
    },
    "cors": {
        "python-fastapi": """# Fix CORS in FastAPI - restrict origins
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[\"https://yourdomain.com\"],  # not [\"*\"]
    allow_origin_regex=r\"https://.*\\.yourdomain\\.com\",
    allow_credentials=True,
    allow_methods=[\"GET\", \"POST\"],
)""",
        "python-django": """# Fix CORS in Django (django-cors-headers)
# settings.py
CORS_ALLOWED_ORIGINS = [\"https://yourdomain.com\"]
CORS_ALLOW_CREDENTIALS = True
# Use regex for subdomains:
CORS_ALLOWED_ORIGIN_REGEXES = [r\"^https://\\w+\\.yourdomain\\.com$\"]""",
        "nodejs-express": """// Fix CORS in Express (cors)
const cors = require('cors');
app.use(cors({
  origin: ['https://yourdomain.com', /https:\\/\\/.*\\.yourdomain\\.com$/],
  credentials: true,
}));""",
        "php": """// Fix CORS in PHP
header(\"Access-Control-Allow-Origin: https://yourdomain.com\");
header(\"Access-Control-Allow-Credentials: true\");
// Avoid: header(\"Access-Control-Allow-Origin: *\"); with credentials""",
    },
    "idor": {
        "python-fastapi": """# Fix IDOR/BOLA in FastAPI - enforce owner check
from fastapi import Depends, HTTPException
async def get_project(project_id: str, current_user=Depends(get_current_user), db=Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id==project_id, Project.owner_id==current_user.id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(403, \"Not authorized for this resource\")
    return project""",
        "python-django": """# Fix IDOR in Django - check ownership
def get_object(request, pk):
    obj = get_object_or_404(Project, pk=pk)
    if obj.owner != request.user:
        raise PermissionDenied(\"Not authorized\")
    return obj""",
        "nodejs-express": """// Fix IDOR in Express - verify owner
app.get('/api/projects/:id', async (req, res) => {
  const project = await Project.findOne({ where: { id: req.params.id, ownerId: req.user.id } });
  if (!project) return res.status(403).json({detail: 'Not authorized'});
  res.json(project);
});""",
        "php": """// Fix IDOR in PHP - check session owner
$stmt = $pdo->prepare(\"SELECT * FROM projects WHERE id = :id AND owner_id = :uid\");
$stmt->execute(['id'=>$id, 'uid'=>$_SESSION['user_id']]);
if (!$stmt->fetch()) { http_response_code(403); exit('Not authorized'); }""",
    },
}

_DEFAULT_SNIPPET = """# Remediation: follow OWASP cheat sheet for {vuln}
# Validate input, use parameterized queries, enforce access control, and sanitize output.
# See https://cheatsheetseries.owasp.org/"""


def get_snippet(vuln_type: str, tech_stack: str) -> str:
    """Get remediation snippet for vuln+stack, fallback to default."""
    vt = vuln_type.lower().strip().replace(" ", "-")
    # Normalize vuln aliases
    aliases = {
        "sql-injection": "sqli",
        "sql": "sqli",
        "cross-site-scripting": "xss",
        "cors-misconfig": "cors",
        "bola": "idor",
    }
    vt = aliases.get(vt, vt)
    # Normalize stack
    ts = tech_stack.lower().strip()
    # Direct match
    stack_map = _SNIPPETS.get(vt, {})
    if ts in stack_map:
        return stack_map[ts]
    # Partial match
    for k, v in stack_map.items():
        if ts in k or k in ts:
            return v
    # Fallback to python-fastapi as default stack for this vuln
    if stack_map:
        return next(iter(stack_map.values()))
    return _DEFAULT_SNIPPET.format(vuln=vt)


def list_supported() -> Dict[str, list]:
    """Return supported vuln types and stacks."""
    return {"vulns": list(_SNIPPETS.keys()), "stacks": ["python-fastapi", "python-django", "nodejs-express", "php"]}
