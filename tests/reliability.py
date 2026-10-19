"""Run hosted-coordinator reliability checks against a new, disposable PostgreSQL cluster."""

import argparse, concurrent.futures, hashlib, json, os, pathlib, runpy, socket, subprocess, time, urllib.request, uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--pg-bin", type=pathlib.Path, required=True)
    parser.add_argument("--publications", type=int, default=52)
    args = parser.parse_args()
    assert 1 <= args.publications <= 200
    binary = args.binary.resolve()
    assert binary.is_file()
    root = ROOT / ".tools" / ("reliability-" + uuid.uuid4().hex)
    root.mkdir(parents=True)
    (root / "reliability-run.json").write_text("{}")
    db = root / "postgres"
    pgport = free_port()
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    database = f"postgres://reliability@127.0.0.1:{pgport}/postgres"
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    results = []
    process = None
    started = False
    previous = pathlib.Path.cwd()
    os.chdir(ROOT)

    def pg(name, *values):
        suffix = ".exe" if os.name == "nt" else ""
        return [str(args.pg_bin.resolve() / (name + suffix)), *map(str, values)]

    def run_pg(name, *values):
        with (root / "postgres-control.log").open("a", encoding="utf8") as log:
            subprocess.run(
                pg(name, *values),
                check=True,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=flags,
                timeout=45,
            )

    def sql(statement):
        return subprocess.check_output(
            pg(
                "psql",
                "-h",
                "127.0.0.1",
                "-p",
                pgport,
                "-U",
                "reliability",
                "-d",
                "postgres",
                "-v",
                "ON_ERROR_STOP=1",
                "-At",
                "-c",
                statement,
            ),
            text=True,
            creationflags=flags,
        )

    environment = {
        **os.environ,
        "DATABASE_URL": database,
        "MCOLLAB_TEST_DATABASE_URL": database,
        "PUBLIC_URL": url,
        "BIND_ADDR": f"127.0.0.1:{port}",
        "MCOLLAB_TEST_URL": url,
        "PSQL": str(
            args.pg_bin.resolve() / ("psql.exe" if os.name == "nt" else "psql")
        ),
    }

    def start():
        nonlocal process
        with (root / "service.log").open("a", encoding="utf8") as log:
            process = subprocess.Popen(
                [str(binary)],
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=flags,
            )
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(120):
            try:
                assert op.open(url + "/health", timeout=1).read() == b"ok"
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("Disposable service did not start")

    def stop():
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=15)

    def record(name, action):
        at = time.monotonic()
        try:
            action()
            results.append(
                dict(
                    name=name,
                    status="passed",
                    durationMs=round((time.monotonic() - at) * 1000),
                )
            )
            print("PASS " + name, flush=True)
        except Exception as error:
            results.append(dict(name=name, status="failed", error=type(error).__name__))
            raise

    try:
        run_pg(
            "initdb",
            "-D",
            db,
            "-U",
            "reliability",
            "-A",
            "trust",
            "--no-locale",
            "-E",
            "UTF8",
        )
        run_pg(
            "pg_ctl",
            "-D",
            db,
            "-l",
            root / "postgres.log",
            "-o",
            f"-h 127.0.0.1 -p {pgport}",
            "-w",
            "-t",
            "20",
            "start",
        )
        started = True
        start()
        os.environ.update(environment)
        context = {}
        record(
            "hosted encrypted membership, locks and atomic publication",
            lambda: context.update(
                runpy.run_path(str(ROOT / "tests/service-integration.py"))
            ),
        )
        request = context["request"]
        base = context["base"]
        pid = context["pid"]
        owner = context["t"]
        guest = context["g"]
        before = request(base, token=owner)[1]["sequence"]

        def restart():
            stop()
            start()
            assert request(base, token=owner)[1]["sequence"] == before

        record(
            "process restart retains authoritative PostgreSQL history and credentials",
            restart,
        )

        def expiry():
            status, lease = request(base + "/locks/acquire", dict(section="31"), owner)
            assert status == 200
            alias = context["codec"](
                pid, "encode", "/locks/acquire", dict(section="31")
            )["section"]
            assert all(c in "0123456789abcdef" for c in alias)
            # This test database belongs to this run only, so changing its expiry times is safe.
            sql(
                f"UPDATE projects SET state=jsonb_set(state,ARRAY['locks','{alias}','expires'],'0'::jsonb) WHERE id='{pid}'"
            )
            status, new = request(base + "/locks/acquire", dict(section="31"), guest)
            assert status == 200 and new["fence"] > lease["fence"]
            assert (
                request(
                    base + "/locks/renew",
                    dict(section="31", fence=lease["fence"]),
                    owner,
                )[0]
                == 409
            )
            revision = context["rev"]("31", "e")
            update = dict(
                id=str(uuid.uuid4()),
                summary="Expired-owner private changelog",
                details="",
                revisions=[revision],
                fences={"31": lease["fence"]},
                restores=None,
            )
            assert request(base + "/publish", update, owner)[0] == 409
            assert "31" not in request(base, token=owner)[1]["heads"]

        record(
            "controlled expiry and takeover fence stale renewals and publications",
            expiry,
        )

        def publish(index):
            section = str(40 + index % 24)
            status, lease = request(
                base + "/locks/acquire", dict(section=section), owner
            )
            assert status == 200
            head = request(base, token=owner)[1]["heads"].get(section)
            revision = context["rev"](section, "d", head["hash"] if head else None)
            revision["hash"] = hashlib.sha256(f"synthetic-{index}".encode()).hexdigest()
            update = dict(
                id=str(uuid.uuid4()),
                summary=f"Private reliability cycle {index}",
                details="",
                revisions=[revision],
                fences={section: lease["fence"]},
                restores=None,
            )
            status, first = request(base + "/publish", update, owner)
            assert status == 200, first
            status, retry = request(base + "/publish", update, owner)
            assert (
                status == 200
                and retry["id"] == first["id"]
                and retry["sequence"] == first["sequence"]
            )
            return first["id"]

        def repeated():
            ids = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                for offset in range(0, args.publications, 8):
                    ids.extend(
                        pool.map(
                            publish, range(offset, min(offset + 8, args.publications))
                        )
                    )
            assert len(set(ids)) == args.publications
            assert (
                request(base, token=owner)[1]["sequence"] == before + args.publications
            )
            page = request(base + "/history", token=owner)[1]
            all_entries = page["entries"]
            while page.get("next"):
                page = request(
                    base + "/history?before=" + str(page["next"]), token=owner
                )[1]
                all_entries += page["entries"]
            assert len(all_entries) == before + args.publications
            assert [entry["sequence"] for entry in all_entries] == list(
                range(before + args.publications, 0, -1)
            )
            assert len({entry["id"] for entry in all_entries}) == len(all_entries)

        record(
            "concurrent repeated publications are unique, ordered, idempotent and paginated",
            repeated,
        )

        def privacy():
            stored = sql(
                "SELECT coalesce(json_agg(doc),'[]'::json) FROM (SELECT state::json AS doc FROM projects UNION ALL SELECT document::json AS doc FROM updates) rows"
            )
            for private in [
                "Private reliability cycle",
                "Expired-owner private changelog",
                "Fixed the boat deck",
                "No more falling through.",
            ]:
                assert private not in stored
            for bundle in context["FIXTURE_KEYS"].values():
                assert bundle not in stored
            for row in json.loads(stored):
                assert not set(row) & {
                    "name",
                    "storage",
                    "section_names",
                    "summary",
                    "details",
                    "author",
                    "nameChanges",
                }
            assert "invite_bootstraps" in stored

        record(
            "coordinator database contains control receipts, expiring locators and no descriptions or keys",
            privacy,
        )
    finally:
        stop()
        if started:
            run_pg("pg_ctl", "-D", db, "-w", "-t", "20", "stop", "-m", "fast")
        os.chdir(previous)
        (root / "report.json").write_text(
            json.dumps(
                dict(
                    publications=args.publications,
                    scenarios=results,
                    limits=[
                        "Synthetic metadata and controlled expiry, not live provider permissions"
                    ],
                ),
                indent=2,
            ),
            encoding="utf8",
        )
        print("REPORT " + str(root / "report.json"), flush=True)


if __name__ == "__main__":
    main()
