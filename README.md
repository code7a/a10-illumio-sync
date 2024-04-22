# a10-illumio-sync

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License. You may obtain a copy of
the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.

```
jq is required to parse results
https://stedolan.github.io/jq/

usage: ./a10-illumio-sync.sh [options]

options:
    --get-a10-vips          get a10 lb vips
    --get-a10-acls          get a10 lb acls
    --get-a10-snat-pools    get a10 lb snat pools
    --sync-vips             creates illumio unmanaged workloads from a10 lb vips
    --sync-rules            creates/updates a10 vip acls from illumio rules
    --sync-snat-pools       creates/updates illumio ip lists from a10 lb snat pools
```