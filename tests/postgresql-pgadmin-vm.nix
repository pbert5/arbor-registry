{ modules, pkgs }:
pkgs.testers.nixosTest {
  name = "arbor-registry-postgresql-pgadmin";
  nodes.machine = { ... }: {
    imports = modules;
    system.stateVersion = "25.05";
    virtualisation.memorySize = 2048;
    cluster.registry.runtime.enable = true;
    services.postgresql.settings.port = 5544;
    cluster.registry.postgresql = {
      enable = true;
      pgadmin = {
        enable = true;
        initialEmail = "admin@example.com";
        initialPasswordFile = "/run/pgadmin-test-password";
      };
    };
    systemd.tmpfiles.rules = [ "f /run/pgadmin-test-password 0600 root root - testpassword" ];
    environment.systemPackages = [
      pkgs.python3
      pkgs.curl
      pkgs.jq
    ];
  };
  testScript = ''
    import shlex

    machine.start()
    machine.wait_for_unit("arbor-registry.service")
    machine.wait_for_unit("pgadmin.service")
    machine.wait_until_succeeds("curl -fsS http://127.0.0.1:5050/login >/dev/null")
    machine.succeed(r"""python3 - <<'PY'
    import http.cookiejar, json, re, urllib.parse, urllib.request
    base = "http://127.0.0.1:5050"
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    page = opener.open(base + "/login").read().decode()
    token = json.loads(re.search(r'"csrfToken":\s*("[^"]+")', page).group(1))
    form = urllib.parse.urlencode({"email": "admin@example.com", "password": "testpassword", "csrf_token": token}).encode()
    login_url = json.loads(re.search(r'"loginUrl":\s*("[^"]+")', page).group(1))
    response = opener.open(base + login_url, form)
    assert "/login" not in response.url, response.url
    request = urllib.request.Request(base + "/browser/server/connect/1/1", data=b"{}", headers={"Content-Type": "application/json", "X-pgA-CSRFToken": token})
    try:
        result = json.load(opener.open(request))
    except urllib.error.HTTPError as error:
        raise RuntimeError(error.read().decode()) from error
    assert result.get("success") == 1, result
    PY""")
    machine.succeed("ss -ltn | grep '127.0.0.1:5050'")
    machine.fail("ss -ltn | grep -E '(0.0.0.0|\\[::\\]):5050'")
    machine.succeed("runuser -u arbor-registry -- psql -h /run/postgresql -p 5544 -U arbor-registry -d arbor_registry -v ON_ERROR_STOP=1 -c 'CREATE TABLE readonly_test (value integer); INSERT INTO readonly_test VALUES (1)'")
    machine.succeed("runuser -u pgadmin -- psql -h /run/postgresql -p 5544 -U arbor_registry_readonly -d arbor_registry -v ON_ERROR_STOP=1 -c 'SELECT * FROM readonly_test'")
    machine.fail("runuser -u pgadmin -- psql -h /run/postgresql -p 5544 -U arbor_registry_readonly -d arbor_registry -v ON_ERROR_STOP=1 -c 'INSERT INTO readonly_test VALUES (2)'")
    machine.fail("runuser -u pgadmin -- psql -h /run/postgresql -p 5544 -U arbor_registry_readonly -d arbor_registry -v ON_ERROR_STOP=1 -c 'CREATE TABLE forbidden (value integer)'")
    machine.fail("runuser -u arbor-registry -- psql -h /run/postgresql -p 5544 -U arbor_registry_readonly -d arbor_registry -c 'SELECT 1'")
    machine.succeed("systemctl restart postgresql.service")
    machine.wait_for_unit("arbor-registry.service")
    machine.wait_until_succeeds("runuser -u arbor-registry -- psql -h /run/postgresql -p 5544 -U arbor-registry -d arbor_registry -c 'SELECT 1'")
    status_request = "import json, socket; s = socket.socket(socket.AF_UNIX); s.connect('/run/arbor-registry/registry.sock'); token = open('/run/arbor-registry/socket-token').read().strip(); s.sendall((json.dumps({'token': token, 'operation': 'status'}) + chr(10)).encode()); assert json.loads(s.makefile('rb').readline())['ok'] is True"
    machine.wait_until_succeeds("python3 -c " + shlex.quote(status_request))
    machine.succeed("test $(stat -c %a /run/pgadmin-test-password) = 600")
  '';
}
