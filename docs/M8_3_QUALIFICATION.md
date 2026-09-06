# M8.3 — VT-Schutz / AmigaOS 1.3 qualification

## Status

**Adapter/fixture qualification in progress. Runtime qualification pending.**

M8.3 introduces the first concrete historical scanner adapter: VT-Schutz v3.17 under the explicit `os13` profile.

## Code-qualified scope

The M8.3 code path is intended to qualify:

- VT-Schutz engine identity and `os13` restriction;
- conservative parsing of explicit clean, infected and suspicious output fixtures;
- named detection extraction for known fixture forms;
- unknown output remaining `unknown` rather than being promoted to `clean`;
- incomplete runtime becoming `error`;
- exact raw scanner output retained and SHA-256 sealed through the common M8.1 evidence model.

The fixtures are synthetic compatibility fixtures. They do not claim that every literal message used by the real VT-Schutz v3.17 binary has yet been observed.

## Runtime boundary

Actual VT-Schutz v3.17 execution is not part of ordinary CI because the historical scanner and AmigaOS/ROM environment are user-supplied/licensing-sensitive components.

Runtime qualification requires the intended scanner binary to be executed under the M8 `os13` profile against controlled known-clean and known-infected inputs. That qualification must record at least:

- scanner binary SHA-256;
- AmigaOS/ROM/profile identity;
- input SHA-256;
- raw scanner output;
- normalized result;
- evidence that original input was not modified;
- emulator/runtime outcome and timing.

Until that run exists, M8.3 must be described as **adapter/fixture-qualified**, not runtime-qualified or appliance-qualified.

## Next gate

After CI is green for this adapter, the next implementation work may either add the real `os13` invocation automation needed for runtime qualification or continue M8.4 adapters while keeping all of them explicitly fixture-qualified until the user-supplied runtime components are available.
