# Performance Improvements for v2.1

## Identified Bottlenecks

### 1. Get-InactiveUsersWithoutMFA (SLOWEST)
**Issue:** Gets ALL users, then queries auth methods for EACH user serially
**Impact:** 1000 users = 1001 API calls (1 for users, 1000 for auth methods)

**Fixes:**
- Use `-Filter` to only get enabled users
- Use `-Select` to only retrieve needed properties
- Add `-Top` parameter to limit results
- Implement parallel processing for auth method checks
- Cache auth method lookups

### 2. Get-UserConsentedApplications
**Issue:** Gets all permission grants, all service principals, then looks up users
**Impact:** Large tenant = slow

**Fixes:**
- Use `-Filter` on permission grants
- Parallel processing for user lookups
- Cache service principal lookups
- Optional: Add `-Top` parameter

### 3. Get-ExcessiveAppPermissions
**Issue:** Gets ALL service principals
**Impact:** 1000+ service principals = slow

**Fixes:**
- Add `-Filter` for ServicePrincipalType
- Use `-Select` to only get needed properties
- Add `-Top` parameter

### 4. Get-ConditionalAccessExclusions
**Issue:** Individual GUID resolution calls
**Impact:** Many exclusions = many sequential API calls

**Fixes:**
- Batch GUID lookups
- Better caching (already has some)
- Use `-ExpandProperty` where possible

## Implementation Priority

1. **HIGH:** Add parallel processing to auth method lookups
2. **HIGH:** Implement better filtering with `-Filter` parameter
3. **MEDIUM:** Add `-Top` parameter to limit results
4. **MEDIUM:** Use `-Select` for property optimization
5. **LOW:** Implement batching for GUID resolution

## Example Optimizations

### Before (Slow):
```powershell
$users = Get-MgUser -All
foreach ($user in $users) {
    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
}
```

### After (Fast):
```powershell
$users = Get-MgUser -Filter "accountEnabled eq true" -Select Id,DisplayName -Top 1000
$users | ForEach-Object -Parallel {
    $methods = Get-MgUserAuthenticationMethod -UserId $_.Id
} -ThrottleLimit 10
```

**Speed improvement:** ~5-10x faster
