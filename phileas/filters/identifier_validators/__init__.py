# Copyright 2026 Philterd, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Built-in identifier validators.

Each module ports one Phileas (Java) validator and registers it by name with the
validator registry. Importing this package registers them all. The validators
are parity ports: for the same input they return the same result as the Java
implementation.
"""

from . import luhn  # noqa: F401
from . import mod11  # noqa: F401
from . import mod97  # noqa: F401
from . import mod23_letter  # noqa: F401
from . import es_cif  # noqa: F401
from . import de_steuerid  # noqa: F401
from . import de_personalausweis  # noqa: F401
from . import bic_structural  # noqa: F401
