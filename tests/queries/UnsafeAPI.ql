/**
 * @name Unsafe APIs
 * @description Unsafe APIs
 * @kind problem
 * @problem.severity warning
 * @tags security
 * @id acc/unsafeapis
 * @precision low
 */

import cpp
import Exclusions

class BannedApiFunctionCall extends FunctionCall {
    BannedApiFunctionCall() {
       getTarget().hasGlobalName("_getts")
       or getTarget().hasGlobalName("_gettws")
       or getTarget().hasGlobalName("gets")
       or getTarget().hasGlobalName("memcpy")
       or getTarget().hasGlobalName("strcat")
       or getTarget().hasGlobalName("strcpy")
       or getTarget().hasGlobalName("strncat")
       or getTarget().hasGlobalName("strncpy")
       or getTarget().hasGlobalName("vsprintf")
       or getTarget().hasGlobalName("wcscat")
       or getTarget().hasGlobalName("wcscpy")
       or getTarget().hasGlobalName("wcsncat")
       or getTarget().hasGlobalName("wcsncpy")
    }

    string message() {
       if (getTarget().hasGlobalName("_getts")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'No size limit on data'.Replacement Functions: gets_s")
       else if (getTarget().hasGlobalName("_gettws")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'No size limit on data'.Replacement Functions: gets_s")
       else if (getTarget().hasGlobalName("gets")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'Deprecated by C11 standard'.Replacement Functions: fgets,gets_s")
       else if (getTarget().hasGlobalName("memcpy")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'Limited error detection'.Replacement Functions: memcpy_s")
       else if (getTarget().hasGlobalName("strcat")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'Limited error detection'.Replacement Functions: strcat_s,strncat_s")
       else if (getTarget().hasGlobalName("strcpy")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'No bounds checking'.Replacement Functions: strcpy_s")
       else if (getTarget().hasGlobalName("strncat")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'Limited error detection'.Replacement Functions: strlcat,strncat_s")
       else if (getTarget().hasGlobalName("strncpy")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'Limited error detection'.Replacement Functions: strncpy_s")
       else if (getTarget().hasGlobalName("vsprintf")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'Limited error detection'.Replacement Functions: vsnprintf,vsprintf_s")
       else if (getTarget().hasGlobalName("wcscat")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'Limited error detection'.Replacement Functions: wcscat_s")
       else if (getTarget().hasGlobalName("wcscpy")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'No bounds checking'.Replacement Functions: wcscpy_s")
       else if (getTarget().hasGlobalName("wcsncat")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'Limited error detection'.Replacement Functions: wcsncat_s")
       else if (getTarget().hasGlobalName("wcsncpy")) then(result = "Using banned API: '" + getTarget().getQualifiedName() + "'.Rationale: 'Limited error detection'.Replacement Functions: wcsncpy_s")
      else (result = "Using banned API: '" + getTarget().getQualifiedName() + "'.")
    }
}

from BannedApiFunctionCall bannedCall
where oe_exclude_depends(bannedCall.getFile())
select bannedCall, bannedCall.message()