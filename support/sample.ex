defmodule Vulsweb.Sample do
  @moduledoc """
  Generates realistic vuls (v0.43, jsonVersion 4) result files for
  development and tests. Compiled in :dev and :test only.

      mix vulsweb.gen.sample            # writes ./sample/results
      mix vulsweb.gen.sample /tmp/res   # custom directory
  """

  @cves [
    # id, package(s), v3 score, v3 vector, v4 score, summary, extras
    {"CVE-2024-6387", ["openssh-server", "openssh-client"], 8.1,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.2,
     "A signal handler race condition was found in OpenSSH's server (sshd), where a client does not authenticate within LoginGraceTime seconds, then sshd's SIGALRM handler is called asynchronously and calls various functions that are not async-signal-safe (regreSSHion).",
     [:kev, :exploit, :metasploit], ["CWE-364"]},
    {"CVE-2023-4911", ["glibc", "libc6"], 7.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
     nil,
     "A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the GLIBC_TUNABLES environment variable (Looney Tunables).",
     [:kev, :exploit, :metasploit], ["CWE-787", "CWE-122"]},
    {"CVE-2024-3094", ["xz-utils", "liblzma5"], 10.0,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", nil,
     "Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. The liblzma build process extracts a prebuilt object file from a disguised test file.",
     [:exploit], ["CWE-506"]},
    {"CVE-2023-38545", ["curl", "libcurl4"], 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     nil, "This flaw makes curl overflow a heap based buffer in the SOCKS5 proxy handshake.",
     [:exploit], ["CWE-787"]},
    {"CVE-2024-2961", ["glibc", "libc6"], 7.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:L",
     nil,
     "The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set.",
     [:exploit], ["CWE-787"]},
    {"CVE-2024-6345", ["python3-setuptools"], 8.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
     nil,
     "A vulnerability in the package_index module of pypa/setuptools versions up to 69.1.1 allows for remote code execution via its download functions.",
     [], ["CWE-94"]},
    {"CVE-2023-48795", ["openssh-server", "openssh-client", "libssh2-1"], 5.9,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", nil,
     "The SSH transport protocol with certain OpenSSH extensions allows remote attackers to bypass integrity checks such that some packets are omitted (Terrapin attack).",
     [:exploit], ["CWE-354"]},
    {"CVE-2024-0727", ["openssl", "libssl3"], 5.5, "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
     6.9,
     "Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash leading to a potential Denial of Service attack.",
     [], ["CWE-476"]},
    {"CVE-2023-5678", ["openssl", "libssl3"], 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
     nil,
     "Generating excessively long X9.42 DH keys or checking excessively long X9.42 DH keys or parameters may be very slow.",
     [], ["CWE-754"]},
    {"CVE-2024-28182", ["libnghttp2-14", "nghttp2"], 5.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", nil,
     "nghttp2 is an implementation of the HTTP/2 protocol. The library keeps reading an unbounded number of HTTP/2 CONTINUATION frames even after a stream is reset.",
     [], ["CWE-770"]},
    {"CVE-2024-26130", ["python3-cryptography"], 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", nil,
     "If pkcs12.serialize_key_and_certificates is called with both a certificate whose public key did not match the provided private key and an encryption_algorithm with hmac_hash set, then a NULL pointer dereference would occur.",
     [], ["CWE-476"]},
    {"CVE-2023-52425", ["expat", "libexpat1"], 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", nil,
     "libexpat through 2.5.0 allows a denial of service (resource consumption) because many full reparsings are required in the case of a large token for which multiple buffer fills are needed.",
     [], ["CWE-400"]},
    {"CVE-2024-2511", ["openssl", "libssl3"], 5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
     nil,
     "Some non-default TLS server configurations can cause unbounded memory growth when processing TLSv1.3 sessions.",
     [], ["CWE-1325"]},
    {"CVE-2022-48174", ["busybox"], 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil,
     "There is a stack overflow vulnerability in ash.c:6030 in busybox before 1.35. In the environment of Internet of Vehicles, this vulnerability can be executed from command to arbitrary code execution.",
     [], ["CWE-787"]},
    {"CVE-2024-45490", ["expat", "libexpat1"], 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil,
     "An issue was discovered in libexpat before 2.6.3. xmlparse.c does not reject a negative length for XML_ParseBuffer.",
     [], ["CWE-611"]},
    {"CVE-2023-29491", ["ncurses", "libncursesw6"], 7.8,
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", nil,
     "ncurses before 6.4 20230408, when used by a setuid application, allows local users to trigger security-relevant memory corruption via malformed data in a terminfo database file.",
     [], ["CWE-787"]},
    {"CVE-2022-3219", ["gnupg", "gpg"], 3.3, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", nil,
     "GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.",
     [], ["CWE-787"]},
    {"CVE-2016-2781", ["coreutils"], 6.5, "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N", nil,
     "chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.",
     [], ["CWE-20"]},
    {"CVE-2017-11164", ["libpcre3", "pcre"], 7.5, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
     nil,
     "In PCRE 8.41, the OP_KETRMAX feature in the match function in pcre_exec.c allows stack exhaustion (uncontrolled recursion) when processing a crafted regular expression.",
     [], ["CWE-674"]},
    {"CVE-2024-0553", ["gnutls28", "libgnutls30"], 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", nil,
     "A vulnerability was found in GnuTLS. The response times to malformed ciphertexts in RSA-PSK ClientKeyExchange differ from the response times of ciphertexts with correct PKCS#1 v1.5 padding.",
     [], ["CWE-203"]},
    {"CVE-2023-7008", ["systemd", "libsystemd0"], 5.9,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", nil,
     "A vulnerability was found in systemd-resolved. This issue may allow systemd-resolved to accept records of DNSSEC-signed domains even when they have no signature.",
     [], ["CWE-300"]},
    {"CVE-2024-22365", ["pam", "libpam0g"], 5.5, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
     nil,
     "linux-pam (aka Linux PAM) before 1.6.0 allows attackers to cause a denial of service (blocked login process) via mkfifo because the openat call (for protect_dir) lacks O_DIRECTORY.",
     [], ["CWE-400"]},
    {"CVE-2023-50495", ["ncurses", "libncursesw6"], 6.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", nil,
     "NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().",
     [], []},
    {"CVE-2024-7348", ["postgresql-16", "postgresql"], 7.5,
     "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H", nil,
     "Time-of-check Time-of-use (TOCTOU) race condition in pg_dump in PostgreSQL allows an object creator to execute arbitrary SQL functions as the user running pg_dump.",
     [], ["CWE-367"]},
    {"CVE-2024-31449", ["redis"], 7.0, "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", nil,
     "Redis is an open source, in-memory database that persists on disk. An authenticated user may use a specially crafted Lua script to trigger a stack overflow in the bit library.",
     [], ["CWE-121"]},
    {"CVE-2024-38475", ["apache2", "httpd"], 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     nil,
     "Improper escaping of output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to map URLs to filesystem locations that are permitted to be served by the server.",
     [:kev], ["CWE-116"]},
    {"CVE-2024-1086", ["linux-image-generic", "kernel"], 7.8,
     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", nil,
     "A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation.",
     [:kev, :exploit], ["CWE-416"]}
  ]

  @hosts [
    %{
      name: "web01",
      family: "ubuntu",
      release: "24.04",
      kernel: "6.8.0-45-generic",
      ip: "10.0.1.11",
      content: "ubuntu",
      pkgs:
        ~w(openssh-server openssh-client libc6 xz-utils liblzma5 curl libcurl4 libssl3 openssl apache2 libexpat1 libnghttp2-14 coreutils libpcre3 libgnutls30 libsystemd0 systemd libpam0g gpg libncursesw6 python3-setuptools python3-cryptography linux-image-generic bash ca-certificates tzdata),
      reboot: true
    },
    %{
      name: "web02",
      family: "ubuntu",
      release: "22.04",
      kernel: "5.15.0-119-generic",
      ip: "10.0.1.12",
      content: "ubuntu",
      pkgs:
        ~w(openssh-server openssh-client libc6 curl libcurl4 libssl3 openssl apache2 libexpat1 coreutils libpcre3 libgnutls30 libsystemd0 systemd gpg libncursesw6 linux-image-generic bash tzdata),
      reboot: false
    },
    %{
      name: "db01",
      family: "redhat",
      release: "9.4",
      kernel: "5.14.0-427.13.1.el9_4.x86_64",
      ip: "10.0.2.21",
      content: "redhat_api",
      pkgs:
        ~w(openssh-server openssh-clients glibc curl openssl expat nghttp2 coreutils pcre gnutls systemd pam gnupg2 ncurses postgresql kernel bash),
      reboot: false
    },
    %{
      name: "mon01",
      family: "debian",
      release: "12",
      kernel: "6.1.0-25-amd64",
      ip: "10.0.3.31",
      content: "debian_security_tracker",
      pkgs:
        ~w(openssh-server openssh-client libc6 curl libcurl4 libssl3 openssl libexpat1 libnghttp2-14 coreutils libpcre3 libgnutls30 libsystemd0 systemd libpam0g gpg libncursesw6 libssh2-1 bash),
      reboot: false
    },
    %{
      name: "redis@docker01",
      server: "docker01",
      container: "redis",
      family: "alpine",
      release: "3.19.1",
      kernel: "",
      ip: "10.0.4.41",
      content: "alpine",
      pkgs: ~w(busybox openssl libssl3 redis expat ncurses),
      reboot: false
    }
  ]

  @doc "Writes sample results under `dir`, three scans per host. Returns the file paths."
  def generate(dir, opts \\ []) do
    now = Keyword.get(opts, :now, DateTime.utc_now() |> DateTime.truncate(:second))
    scans = Keyword.get(opts, :scans, 3)
    :rand.seed(:exsss, {7, 42, 1337})

    for host <- @hosts, n <- (scans - 1)..0//-1 do
      # Hosts POST at slightly different times, as with `vuls server`.
      at =
        now
        |> DateTime.add(-n * 86_400, :second)
        |> DateTime.add(-:erlang.phash2(host.name, 3600), :second)

      doc = result(host, at, n)
      sub = Path.join(dir, dirname(at))
      File.mkdir_p!(sub)
      path = Path.join(sub, host.name <> ".json")
      File.write!(path, Jason.encode_to_iodata!(doc, pretty: true))
      # Backdate the file so the store's settle delay never skips it.
      File.touch!(path, DateTime.to_unix(at))
      path
    end
  end

  @doc "Name of the results sub directory vuls uses for a scan time."
  def dirname(%DateTime{} = at), do: Calendar.strftime(at, "%Y-%m-%dT%H-%M-%S+0000")

  # Older scans have a few more CVEs (fixed since), newest the fewest.
  defp result(host, at, age) do
    installed = MapSet.new(host.pkgs)

    cves =
      @cves
      |> Enum.filter(fn {_, pkgs, _, _, _, _, _, _} -> Enum.any?(pkgs, &(&1 in installed)) end)
      |> Enum.with_index()
      |> Enum.reject(fn {_, i} -> age == 0 and rem(i + :erlang.phash2(host.name), 7) == 0 end)
      |> Enum.reject(fn {_, i} -> age == 1 and rem(i + :erlang.phash2(host.name), 11) == 0 end)
      |> Enum.map(&elem(&1, 0))

    packages =
      Map.new(host.pkgs, fn name ->
        upgradable = rem(:erlang.phash2({name, host.name}), 3) != 0

        {name,
         %{
           "name" => name,
           "version" => "#{1 + rem(:erlang.phash2(name), 9)}.#{rem(:erlang.phash2(name), 20)}",
           "release" => release_tag(host.family),
           "newVersion" =>
             if(upgradable,
               do: "#{1 + rem(:erlang.phash2(name), 9)}.#{rem(:erlang.phash2(name), 20) + 1}",
               else: ""
             ),
           "newRelease" => if(upgradable, do: release_tag(host.family), else: ""),
           "arch" => if(host.family == "redhat", do: "x86_64", else: "amd64"),
           "repository" => "",
           "modularitylabel" => ""
         }}
      end)

    scanned =
      Map.new(cves, fn cve -> {elem(cve, 0), vuln(cve, host, installed, packages)} end)

    %{
      "jsonVersion" => 4,
      "lang" => "",
      "serverUUID" => "",
      "serverName" => Map.get(host, :server, host.name),
      "family" => host.family,
      "release" => host.release,
      "container" => %{
        "containerID" => if(host[:container], do: "3f9a1c2b7d4e", else: ""),
        "name" => host[:container] || "",
        "image" => if(host[:container], do: "redis:7.2-alpine", else: ""),
        "type" => if(host[:container], do: "docker", else: ""),
        "uuid" => ""
      },
      "platform" => %{"name" => "other", "instanceID" => ""},
      "ipv4Addrs" => [host.ip],
      "scannedAt" => DateTime.to_iso8601(at),
      "scanMode" => "fast mode",
      "scannedVersion" => "v0.43.0",
      "scannedRevision" => "build-20261118_100620_e11bf47",
      "scannedBy" => Map.get(host, :server, host.name),
      "scannedVia" => "server",
      "reportedAt" => DateTime.to_iso8601(DateTime.add(at, 5, :second)),
      "reportedVersion" => "v0.43.0",
      "reportedRevision" => "build-20261118_100620_e11bf47",
      "reportedBy" => "vuls-server",
      "errors" => [],
      "warnings" =>
        if(host.family == "debian" and age == 0,
          do: ["Some warnings occurred: apt-get update failed for 1 repository"],
          else: []
        ),
      "scannedCves" => scanned,
      "runningKernel" => %{
        "release" => host.kernel,
        "version" => "",
        "rebootRequired" => host.reboot
      },
      "packages" => packages,
      "config" => %{"scan" => %{}, "report" => %{}},
      "cweDict" => cwe_dict(cves)
    }
  end

  defp vuln({id, pkgs, v3, v3vec, v4, summary, extras, cwes}, host, installed, packages) do
    affected =
      for p <- pkgs, p in installed do
        unfixed = rem(:erlang.phash2({id, host.name, p}), 5) == 0

        %{"name" => p}
        |> maybe_put("notFixedYet", unfixed)
        |> maybe_put("fixState", if(unfixed, do: "Will not fix"))
        |> maybe_put(
          "fixedIn",
          if(not unfixed and packages[p]["newVersion"] != "",
            do: packages[p]["newVersion"] <> "-" <> packages[p]["newRelease"]
          )
        )
      end

    published =
      "20#{String.slice(id, 6, 2)}-0#{rem(:erlang.phash2(id), 9) + 1}-1#{rem(:erlang.phash2(id), 9)}T12:00:00Z"

    severity = severity(v3)

    nvd = %{
      "type" => "nvd",
      "cveID" => id,
      "title" => "",
      "summary" => summary,
      "cvss2Score" => 0,
      "cvss2Vector" => "",
      "cvss2Severity" => "",
      "cvss3Score" => v3,
      "cvss3Vector" => v3vec,
      "cvss3Severity" => severity,
      "cvss40Score" => v4 || 0,
      "cvss40Vector" =>
        if(v4, do: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", else: ""),
      "cvss40Severity" => if(v4, do: severity(v4), else: ""),
      "sourceLink" => "https://nvd.nist.gov/vuln/detail/#{id}",
      "references" => [
        %{"link" => "https://www.cve.org/CVERecord?id=#{id}", "source" => "MITRE", "tags" => []},
        %{
          "link" => "https://security-tracker.debian.org/tracker/#{id}",
          "source" => "debian",
          "tags" => ["Third Party Advisory"]
        }
      ],
      "cweIDs" => cwes,
      "published" => published,
      "lastModified" => "2026-10-01T08:00:00Z",
      "optional" => %{"source" => "nvd@nist.gov"}
    }

    distro =
      %{
        "type" => host.content,
        "cveID" => id,
        "title" => id,
        "summary" => summary,
        "cvss2Score" => 0,
        "cvss2Vector" => "",
        "cvss2Severity" => "",
        "cvss3Score" => if(host.content == "redhat_api", do: v3 - 0.4, else: 0),
        "cvss3Vector" => if(host.content == "redhat_api", do: v3vec, else: ""),
        "cvss3Severity" => distro_severity(host.content, v3),
        "cvss40Score" => 0,
        "cvss40Vector" => "",
        "cvss40Severity" => "",
        "sourceLink" => distro_link(host.content, id),
        "published" => published,
        "lastModified" => "2026-10-02T08:00:00Z"
      }

    %{
      "cveID" => id,
      "confidences" => [%{"score" => 100, "detectionMethod" => detection(host.family)}],
      "affectedPackages" => affected,
      "distroAdvisories" =>
        if(host.family == "redhat",
          do: [
            %{
              "advisoryID" => "RHSA-2026:#{1000 + rem(:erlang.phash2(id), 8999)}",
              "severity" => distro_severity("redhat_api", v3),
              "issued" => published,
              "updated" => "2026-10-02T00:00:00Z",
              "description" => "Security update for #{hd(pkgs)}"
            }
          ],
          else: []
        ),
      "cveContents" => %{"nvd" => [nvd], host.content => [distro]},
      "exploits" =>
        if(:exploit in extras,
          do: [
            %{
              "exploitType" => "GitHub",
              "id" => id,
              "url" => "https://github.com/search?q=#{id}",
              "description" => "Proof of concept for #{id}"
            }
          ],
          else: []
        ),
      "metasploits" =>
        if(:metasploit in extras,
          do: [
            %{
              "name" => "exploit/linux/local/#{String.downcase(String.replace(id, "-", "_"))}",
              "title" => "Metasploit module for #{id}",
              "URLs" => ["https://www.rapid7.com/db/?q=#{id}"]
            }
          ],
          else: []
        ),
      "mitigations" => [],
      "kevs" =>
        if(:kev in extras,
          do: [
            %{
              "type" => "cisa",
              "vendor_project" => "Various",
              "product" => hd(pkgs),
              "vulnerability_name" => "#{hd(pkgs)} vulnerability",
              "short_description" => summary,
              "required_action" =>
                "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
              "known_ransomware_campaign_use" => "Unknown",
              "date_added" => "2026-02-01T00:00:00Z",
              "due_date" => "2026-02-22T00:00:00Z"
            }
          ],
          else: []
        ),
      "alertDict" => %{"cisa" => [], "jpcert" => [], "uscert" => []}
    }
  end

  defp cwe_dict(cves) do
    names = %{
      "364" => "Signal Handler Race Condition",
      "787" => "Out-of-bounds Write",
      "122" => "Heap-based Buffer Overflow",
      "506" => "Embedded Malicious Code",
      "94" => "Improper Control of Generation of Code ('Code Injection')",
      "354" => "Improper Validation of Integrity Check Value",
      "476" => "NULL Pointer Dereference",
      "754" => "Improper Check for Unusual or Exceptional Conditions",
      "770" => "Allocation of Resources Without Limits or Throttling",
      "400" => "Uncontrolled Resource Consumption",
      "611" => "Improper Restriction of XML External Entity Reference",
      "20" => "Improper Input Validation",
      "674" => "Uncontrolled Recursion",
      "203" => "Observable Discrepancy",
      "300" => "Channel Accessible by Non-Endpoint",
      "367" => "Time-of-check Time-of-use (TOCTOU) Race Condition",
      "121" => "Stack-based Buffer Overflow",
      "116" => "Improper Encoding or Escaping of Output",
      "416" => "Use After Free",
      "1325" => "Improperly Controlled Sequential Memory Allocation"
    }

    for {_, _, _, _, _, _, _, cwes} <- cves,
        "CWE-" <> num <- cwes,
        into: %{} do
      {num,
       %{
         "en" => %{"cweID" => num, "name" => Map.get(names, num, "CWE-#{num}")},
         "owaspTopTens" => %{},
         "cweTopTwentyfives" => if(num in ~w(787 416 20 476 94), do: %{"2024" => "1"}, else: %{}),
         "sansTopTwentyfives" => %{}
       }}
    end
  end

  defp maybe_put(map, _k, nil), do: map
  defp maybe_put(map, _k, false), do: map
  defp maybe_put(map, k, v), do: Map.put(map, k, v)

  defp severity(s) when s >= 9.0, do: "CRITICAL"
  defp severity(s) when s >= 7.0, do: "HIGH"
  defp severity(s) when s >= 4.0, do: "MEDIUM"
  defp severity(_), do: "LOW"

  defp distro_severity("redhat_api", s) when s >= 9.0, do: "Critical"
  defp distro_severity("redhat_api", s) when s >= 7.0, do: "Important"
  defp distro_severity("redhat_api", s) when s >= 4.0, do: "Moderate"
  defp distro_severity("redhat_api", _), do: "Low"
  defp distro_severity("debian_security_tracker", s) when s >= 7.0, do: "medium|high"
  defp distro_severity("debian_security_tracker", _), do: "low"
  defp distro_severity("alpine", _), do: ""
  defp distro_severity(_, s) when s >= 7.0, do: "high"
  defp distro_severity(_, s) when s >= 4.0, do: "medium"
  defp distro_severity(_, _), do: "low"

  defp distro_link("ubuntu", id), do: "https://ubuntu.com/security/#{id}"
  defp distro_link("redhat_api", id), do: "https://access.redhat.com/security/cve/#{id}"

  defp distro_link("debian_security_tracker", id),
    do: "https://security-tracker.debian.org/tracker/#{id}"

  defp distro_link(_, id), do: "https://security.alpinelinux.org/vuln/#{id}"

  defp detection("ubuntu"), do: "UbuntuAPIMatch"
  defp detection("redhat"), do: "RedHatAPIMatch"
  defp detection("debian"), do: "DebianSecurityTrackerMatch"
  defp detection(_), do: "OvalMatch"

  defp release_tag("ubuntu"), do: "0ubuntu1"
  defp release_tag("redhat"), do: "el9_4"
  defp release_tag("debian"), do: "1+deb12u1"
  defp release_tag(_), do: "r0"
end
