"""Feature 004 fixture workspaces: reproductions of the evidenced misses.

Each site is a dict of repo-relative path -> file content. ``build_fixture``
materializes a site into a directory for a full-scan gate run
(tests/benchmark/test_accuracy_benchmark.py::test_defect_class_missed_detection),
while unit tests consume the dicts directly. Every file is synthetic.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------- US1: misconfig

#: Spring security config with the WebSecurityConfig.java:38-40 misses, plus an
#: unclassifiable high-entropy value in a comment (redaction blocks it) to prove
#: rule evaluation is redaction-independent (FR-002). The "good" twin must not fire.
_SPRING_BAD = """package com.example;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

// rollout ref Zk3Lq9Xv2Bn7Rt4Wy8ABCDEGf0Ds (internal tracking, unclassifiable)
// handles password reset links
public class WebSecurityConfig {
    void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .cors().configurationSource(request -> {
                var config = new CorsConfiguration();
                config.setAllowedOrigins(List.of("*"));
                return config;
            });
    }
}
"""

_SPRING_GOOD = """package com.example;

public class TightSecurityConfig {
    void configure(HttpSecurity http) throws Exception {
        http.csrf().and()
            .cors().configurationSource(request -> {
                var config = new CorsConfiguration();
                config.setAllowedOrigins(List.of("https://app.example.com"));
                return config;
            });
    }
}
"""

_NODE_BAD = """const cors = require('cors');
const session = require('express-session');

app.use(cors({ origin: true, credentials: true }));
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: false } }));
"""

_NODE_GOOD = """const cors = require('cors');

app.use(cors({ origin: 'https://app.example.com' }));
"""

_DJANGO_BAD = """DEBUG = True

ALLOWED_HOSTS = ["*"]

CORS_ALLOW_ALL_ORIGINS = True
"""

_DJANGO_GOOD = """DEBUG = False

ALLOWED_HOSTS = ["app.example.com"]

CORS_ALLOW_ALL_ORIGINS = False
"""

_DJANGO_VIEW_BAD = """from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def webhook(request):
    return None
"""

_GO_BAD = """import "crypto/tls"

func client() *http.Client {
	config := &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
}
"""

_GO_GOOD = """import "crypto/tls"

func client() *http.Client {
	config := &tls.Config{MinVersion: tls.VersionTLS13}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
}
"""

SITES: dict[str, dict[str, str]] = {
    "misconfig_spring": {
        "src/main/java/com/example/WebSecurityConfig.java": _SPRING_BAD,
        "src/main/java/com/example/TightSecurityConfig.java": _SPRING_GOOD,
    },
    "misconfig_node": {
        "frontend/server.js": _NODE_BAD,
        "frontend/api.js": _NODE_GOOD,
    },
    "misconfig_django": {
        "config/settings.py": _DJANGO_BAD,
        "config/views.py": _DJANGO_VIEW_BAD,
        "config/prod_settings.py": _DJANGO_GOOD,
    },
    "misconfig_go": {
        "main.go": _GO_BAD,
        "server.go": _GO_GOOD,
    },
}

# ---------------------------------------------------------------- US2: compound

#: Cyclic schema + permitAll /graphql + no depth-limit config anywhere (the
#: Devin-reported sfind-5d77d22 reproduction).
_GRAPHQL_SCHEMA = """type Query {
  article(id: ID!): Article
}

type Article {
  id: ID!
  comments: [Comment]
}

type Comment {
  id: ID!
  article: Article
}
"""

_GRAPHQL_SECURITY = """package com.example;

public class WebSecurityConfig {
    void configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
            .requestMatchers("/graphql").permitAll()
            .anyRequest().authenticated();
    }
}
"""

#: The same site with a depth limit configured — the finding must retract.
_GRAPHQL_DEPTH_CONFIG = "graphql.servlet.max-query-depth=8\n"

#: Seed migration provisioning loginable accounts with a documented shared
#: password (the sfind-3e125c7 reproduction), plus a public login endpoint.
_SEED_SQL = """-- Seed users. All accounts share the password "password123" for the workshop.
INSERT INTO users (email, username, password_hash) VALUES
  ('john@example.com', 'john', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjRZGaa'),
  ('jane@example.com', 'jane', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjRZGaa'),
  ('bob@example.com', 'bob', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjRZGaa');
"""

_LOGIN_CONTROLLER = """package com.example;

public class AuthController {
    // public by design: no authentication annotation
    public Object login(LoginParam param) {
        return null;
    }
}
"""

#: Same seed migration but the only login handler is in an unparsed language,
#: so the public-auth-entrypoint leg cannot be evaluated -> undetermined.
_RUBY_LOGIN = """class AuthController < ApplicationController
  def login
  end
end
"""

SITES.update(
    {
        "compound_graphql_dos": {
            "src/main/resources/schema.graphqls": _GRAPHQL_SCHEMA,
            "src/main/java/com/example/WebSecurityConfig.java": _GRAPHQL_SECURITY,
        },
        "compound_seed_data": {
            "src/main/resources/db/migration/V2__seed_data.sql": _SEED_SQL,
            "src/main/java/com/example/AuthController.java": _LOGIN_CONTROLLER,
        },
        "compound_seed_data_unparsed_login": {
            "src/main/resources/db/migration/V2__seed_data.sql": _SEED_SQL,
            "app/controllers/auth_controller.rb": _RUBY_LOGIN,
        },
    }
)

#: Retraction variant: the DoS site plus a configured depth limit.
SITES["compound_graphql_dos_retracted"] = {
    **SITES["compound_graphql_dos"],
    "src/main/resources/application.properties": _GRAPHQL_DEPTH_CONFIG,
}


# ------------------------------------------------------------- US3: advisories

_NPM_MARKED = {
    "package.json": (
        '{\n  "name": "demo",\n  "dependencies": {\n'
        '    "marked": "^1.1.1",\n    "react": "^18.2.0"\n  }\n}\n'
    ),
    "package-lock.json": (
        '{\n  "name": "demo",\n  "lockfileVersion": 3,\n  "packages": {\n'
        '    "": {"dependencies": {"marked": "^1.1.1", "react": "^18.2.0"}},\n'
        '    "node_modules/marked": {"version": "1.1.1"},\n'
        '    "node_modules/react": {"version": "18.2.0"}\n'
        "  }\n}\n"
    ),
}

_MAVEN_VULN = {
    "pom.xml": (
        "<project>\n  <dependencies>\n"
        "    <dependency>\n      <groupId>org.apache.logging.log4j</groupId>\n"
        "      <artifactId>log4j-core</artifactId>\n      <version>2.14.1</version>\n"
        "    </dependency>\n"
        "    <dependency>\n      <groupId>com.fasterxml.jackson.core</groupId>\n"
        "      <artifactId>jackson-databind</artifactId>\n      <version>2.15.3</version>\n"
        "    </dependency>\n  </dependencies>\n</project>\n"
    ),
}

_PYPI_VULN = {
    "requirements.txt": "urllib3==1.26.4\nrequests==2.31.0\n",
}

_GO_VULN = {
    "go.mod": (
        "module example.com/demo\n\ngo 1.21\n\nrequire (\n"
        "\tgolang.org/x/text v0.3.7\n"
        "\tgithub.com/gin-gonic/gin v1.9.1\n"
        ")\n"
    ),
}

#: Two vulnerable packages in one manifest — the dedupe-collapse regression.
_NPM_TWO_VULN = {
    "package.json": '{\n  "dependencies": {"marked": "^1.1.1", "minimist": "^1.2.5"}}\n',
    "package-lock.json": (
        '{\n  "lockfileVersion": 3,\n  "packages": {\n'
        '    "node_modules/marked": {"version": "1.1.1"},\n'
        '    "node_modules/minimist": {"version": "1.2.5"}\n'
        "  }\n}\n"
    ),
}

SITES.update(
    {
        "advisory_npm_marked": _NPM_MARKED,
        "advisory_maven": _MAVEN_VULN,
        "advisory_pypi": _PYPI_VULN,
        "advisory_go": _GO_VULN,
        "advisory_npm_two_vuln": _NPM_TWO_VULN,
    }
)


def build_fixture(name: str, root: Path) -> Path:
    """Materialize site ``name`` under ``root``."""
    root.mkdir(parents=True, exist_ok=True)
    for relpath, content in SITES[name].items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    return root
