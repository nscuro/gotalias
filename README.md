# Got Alias?



## Usage

```shell
docker compose up -d # Launch Neo4j

go run main.go \
  -github-token <GITHUB_PAT> \
  -osv \
  -ossindex-user <USERNAME> -ossindex-token <TOKEN> \
  -snyk-orgid <ORG_ID> -snyk-tokens <TOKEN1>,<TOKEN2>,<TOKENX> \
  -purls purls.txt
```

> **Note**  
> Data from vulnerability databases that can not be mirrored has to be requested on
> a per-component basis. A list of PURLs can be provided for this purpose.
> To generate a PURL list from multiple CycloneDX BOMs in JSON format:
> ```shell
> for f in ./**/*.json; do jq -r '.components[].purl' $f >> purls.txt; done
> sort -u purls.txt > purls_unique.txt
> ```

### Useful Cypher Queries

```cypher
// Find a specific vulnerability by its ID
MATCH (:Vulnerability {id: "GHSA-5mcr-gq6c-3hq2"})
RETURN *

// Find the top 100 most aliased non-Debian vulnerabilities
MATCH (vuln:Vulnerability)<-[r:ALIASES]-(:Vulnerability)
WHERE NOT vuln.id STARTS WITH "DLA-"
WITH vuln, COUNT(r) as aliasCount
RETURN *
ORDER BY aliasCount DESC
LIMIT 100

// Find all Snyk vulnerabilities and their aliases
MATCH (v:Vulnerability)-[:ALIASES]->(:Vulnerability)
WHERE v.id = STARTS WITH "SNYK-"
RETURN *

// Find all Snyk vulnerabilities that alias more than one CVE
MATCH (v:Vulnerability)-[r:ALIASES]->(a:Vulnerability)
WHERE v.id STARTS WITH "SNYK-"
    AND a.id STARTS WITH "CVE-"
WITH v, COUNT(r) AS rc
WHERE rc > 1
RETURN *
ORDER BY rc DESC

// Find all vulnerabilities for which more than one alias was reported by GitHub
MATCH (v:Vulnerability)-[r:ALIASES]->(:Vulnerability)
WHERE ANY(item IN r.reportedBy WHERE item = "GITHUB")
WITH v, COUNT(r) AS rc
WHERE rc > 1
RETURN *
ORDER BY rc
LIMIT 100
```

### Data Samples

#### [GHSA-qcvw-h34v-c7r9](https://github.com/pjsip/pjproject/security/advisories/GHSA-qcvw-h34v-c7r9)

Multiple CVEs have been registered for the same GHSA ID.

The official GitHub advisory only refers to `CVE-2021-43299`, but **4** more CVEs link back to the GHSA ID:

* `CVE-2021-43300`: *Stack overflow in PJSUA API when calling pjsua_recorder_create*
* `CVE-2021-43301`: *Stack overflow in PJSUA API when calling pjsua_playlist_create*
* `CVE-2021-43302`: *Read out-of-bounds in PJSUA API when calling pjsua_recorder_create*
* `CVE-2021-43303`: *Buffer overflow in PJSUA API when calling pjsua_call_dump*

OSV thus reports all those CVEs as aliases for `GHSA-qcvw-h34v-c7r9`.

![Aliases of GHSA-qcvw-h34v-c7r9](.github/images/GHSA-qcvw-h34v-c7r9.png)

Because `GHSA-qcvw-h34v-c7r9` aliases `CVE-2021-43299`, does it mean that it aliases the other 4 CVEs, too?
And does it imply that `CVE-2021-43299` and `CVE-2021-43303` are also identical?
*Technically*, the other CVEs describe different things than `CVE-2021-43299`.

#### [GO-2022-0586](https://pkg.go.dev/vuln/GO-2022-0586)

The `aliases` field[^1] in OSV is misused[^2] by some vulnerability databases. Instead of populating this field with
identifiers of vulnerabilities that are truly *identical*, it is populated with *related*[^3] vulnerabilities.

`GO-2022-0586` is an *advisory* rather than a vulnerability, as it represents an aggregate of multiple vulnerabilities.

![Aliases of GO-2022-0586](.github/images/GO-2022-0586.png)

While there are four pairs of CVEs and GHSAs that indeed alias each other, none of the CVEs or GHSAs actually
alias `GO-2022-0586`; They are simply not the same. It also can not be assumed that any of the GHSAs alias *each other*. The same is true for the CVEs.

#### [CVE-2021-21290](https://nvd.nist.gov/vuln/detail/CVE-2021-21290)

At the time of writing, Snyk has a total of [12 `SNYK-` vulnerabilities assigned](https://security.snyk.io/vuln/?search=CVE-2021-21290) to
`CVE-2021-21290` / `GHSA-5mcr-gq6c-3hq2`. It appears like Snyk created separate vulnerabilities
for each affected `netty` module. The vulnerabilities differ only in their *How to fix?* advice.

![Aliases of CVE-2021-21290](.github/images/CVE-2021-21290.png)

> **Note**  
> Snyk explicitly does *not* state that any of the vulnerabilities it reports in the `problems` field of
> its PURL API[^4] are aliases. It just so happens that oftentimes they are. But there's no guarantee.

[^1]: https://ossf.github.io/osv-schema/#aliases-field
[^2]: https://github.com/google/osv.dev/issues/888
[^3]: https://ossf.github.io/osv-schema/#related-field
[^4]: https://apidocs.snyk.io/?version=2023-03-29#get-/orgs/-org_id-/packages/-purl-/issues