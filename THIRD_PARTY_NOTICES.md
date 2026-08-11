# Third-Party Notices

## NVIDIA SkillSpector (Apache License 2.0)

Some security-scan patterns in `api/index.py` (`_PROMPT_INJECTION_PATTERNS`
and `_CODE_PATTERNS`, sections explicitly marked in the source) are adapted
from [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector), used
under the Apache License, Version 2.0.

- Original copyright: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
- License: Apache License, Version 2.0 -- http://www.apache.org/licenses/LICENSE-2.0
- Source files referenced: `src/skillspector/nodes/analyzers/static_patterns_prompt_injection.py`
  and `static_patterns_data_exfiltration.py`

**Changes made:** the original patterns use a 0.0-1.0 float confidence
score per finding; this project converted each score to skillsmith's
1-10 integer weight scale (`round(confidence * 10)`, minimum 1) and
combined the patterns with skillsmith's own pre-existing, independently
written detection ruleset. Rule IDs from the original work (e.g. "P1",
"E2") are retained in the finding message text for traceability back to
the source category. No code from SkillSpector's AST analysis, taint
tracking, YARA rules, LLM semantic analysis, or MCP-specific analyzers
was used -- only a curated subset of the static regex patterns.

```
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

skillsmith itself remains MIT-licensed (see [LICENSE](https://github.com/Larslllllll/skillsmith/blob/main/LICENSE)
in the main skillsmith repo); this notice covers only the specific
adapted patterns named above, as required by the Apache-2.0 license's
attribution terms.
