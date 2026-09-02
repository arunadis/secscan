"""T019/T020: fixtures for tiered location resolution and probe feasibility.

Two fixtures, both deliberately small:

``unparsed-language``
    A member written in a language the code model has no grammar for. Before
    feature 002 such a repository produced no graph nodes at all, so every finding
    in it was rejected for an unresolvable location and the scan reported nothing —
    silently, as if the code were clean. This fixture is the regression guard for
    SC-001a.

``fixed-prefix-sink``
    A sink that interpolates an untrusted value *after* a scheme and host it pins
    itself. Any probe that has to supply its own origin cannot succeed against it,
    which is why the reviewed benchmark's `http://127.0.0.1:9/...` reproduction
    step could never have worked (FR-009/FR-010).

They are separate from ``single-repo-shop`` on purpose: adding files there would
perturb the seeded-vulnerability counts that existing tests assert against.
"""

from __future__ import annotations

from pathlib import Path

from tests.fixtures.build_fixture import Fixture, SeededVuln

UNPARSED = Fixture(
    name="unparsed-language",
    seeded=[
        SeededVuln(
            key="ruby-sqli",
            cwe="CWE-89",
            file="app/orders.rb",
            symbol="find_by_id",
            note="order id interpolated into SQL; language has no grammar, so the "
            "finding must resolve at file tier rather than be dropped",
        ),
    ],
    files={
        "Gemfile": "source 'https://rubygems.org'\ngem 'activerecord', '6.0.0'\n",
        "app/orders.rb": '''# Order persistence.
class OrderRepository
  def find_by_id(order_id)
    # Seeded flaw: SQL injection (CWE-89).
    ActiveRecord::Base.connection.execute(
      "SELECT * FROM orders WHERE id = '#{order_id}'"
    )
  end

  def find_by_customer(customer)
    ActiveRecord::Base.connection.exec_query(
      "SELECT * FROM orders WHERE customer = $1", "sql", [customer]
    )
  end
end
''',
        "app/admin.rb": '''# Administrative operations.
class Admin
  def delete_user(user_id)
    User.find(user_id).destroy
  end
end
''',
    },
)

FIXED_PREFIX = Fixture(
    name="fixed-prefix-sink",
    seeded=[
        SeededVuln(
            key="unencoded-path-segment",
            cwe="CWE-918",
            file="src/api/client.ts",
            symbol="fetchUser",
            note="id interpolated after a fixed scheme and host: no probe that "
            "supplies its own origin can succeed, so no concrete trigger may be emitted",
        ),
    ],
    files={
        # A genuine browser-only client: an Angular runtime, a static entry
        # document, and no server entry point anywhere. This is the architecture
        # on which server-side request forgery is structurally impossible.
        "package.json": """{
  "name": "fixed-prefix-sink",
  "dependencies": {
    "@angular/core": "9.0.1",
    "@angular/platform-browser": "9.0.1",
    "rxjs": "6.5.4"
  }
}
""",
        "index.html": "<!doctype html>\n<html><body><app-root></app-root></body></html>\n",
        "src/api/client.ts": '''/** Upstream API client. */
export class ApiClient {
  private baseUrl = "https://api.example.com";

  fetchUser(id: string) {
    // The untrusted `id` lands AFTER a scheme and host this method pins itself.
    return fetch(`${this.baseUrl}/user/${id}`).then((r) => r.json());
  }

  fetchFeed(feedType: string, page: number) {
    return fetch(`${this.baseUrl}/${feedType}?page=${page}`).then((r) => r.json());
  }
}
''',
    },
)


def build_unparsed(root: Path) -> Path:
    return UNPARSED.write(root)


def build_fixed_prefix(root: Path) -> Path:
    return FIXED_PREFIX.write(root)
