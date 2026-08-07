function ConvertTo-SAWFido2KeyInventory {
    <#
    .SYNOPSIS
        Resolves the FIDO2 key restrictions allow/block-list into human-readable key names.
    .DESCRIPTION
        A separate data product from ConvertTo-SAWNormalizedPasskeys's derived PASS002
        Enabled/Disabled fact (whether key restrictions are enforced at all) - this answers the
        follow-up question a customer always asks next: "enforced against WHAT, exactly?" Graph
        only returns keyRestrictions.aaGuids as raw GUIDs; on their own they tell an admin
        nothing without cross-referencing a vendor's published list or the FIDO Alliance
        Metadata Service (MDS) by hand.

        The reference table below (see $knownFido2KeyAaguids) is seeded from Yubico's own
        published hardware FIDO2 AAGUID list
        (https://support.yubico.com/hc/en-us/articles/360016648959-YubiKey-hardware-FIDO2-AAGUIDs,
        confirmed current as of this writing) - deliberately not the community
        passkeydeveloper/passkey-authenticator-aaguids list already used by
        ConvertTo-SAWNormalizedPasskeys for synced-passkey detection, since that list is scoped
        to platform authenticators/password managers and does not cover dedicated hardware
        security keys at all. The two lists are combined here so a single AAGUID lookup covers
        both hardware keys and synced-passkey providers.

        Yubico is the only hardware vendor covered right now - by far the most common in
        enterprise Entra deployments, and the only one with a conveniently published, complete
        AAGUID table found during research. Other vendors (Feitian, Google Titan, SoloKeys, and
        so on) are not yet in the reference table. Same "strong signal, not exhaustive proof"
        caveat as the synced-passkey detection: an unrecognized AAGUID is reported as such
        (with a pointer to the FIDO Alliance MDS and the vendor), never silently dropped or
        misrepresented as something it isn't.
    .PARAMETER RawConfig
        The object returned by Get-SAWPasskeys.
    .OUTPUTS
        Hashtable with IsEnforced, EnforcementType, EnforcementSummary, and AllowedKeys (an
        array of hashtables: Aaguid, KnownName, Recognized). Deliberately not named "Keys" -
        that collides with Hashtable's own intrinsic .Keys member (the dictionary's key names),
        which would silently shadow this array on dot-notation access.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$RawConfig
    )

    begin {
        # Yubico hardware FIDO2 AAGUIDs, deduplicated from the vendor's published table (see
        # .DESCRIPTION for the source URL). Multiple product/firmware combinations share the
        # same AAGUID by design (Yubico issues one per capability set, not per SKU), so names
        # here list every product the vendor's table associates with that AAGUID.
        $knownFido2KeyAaguids = @{
            'cb69481e-8ff7-4039-93ec-0a2729a154a8' = 'YubiKey 5 / 5 Nano / 5C / 5C Nano (fw 5.1, FIDO L1)'
            'ee882879-721c-4913-9775-3dfcce97072a' = 'YubiKey 5 / 5 Nano / 5C / 5C Nano / CSPN variants (fw 5.2-5.4, FIDO L1)'
            'fa2b99dc-9e39-4257-8f92-4a30d23c4118' = 'YubiKey 5 NFC (fw 5.1, FIDO L1)'
            '2fc0579f-8113-47ea-b116-bb5a8db9202a' = 'YubiKey 5 NFC / 5C NFC / CSPN variants (fw 5.2-5.4, FIDO L1)'
            'a25342c0-3cdc-4414-8e46-f4807fca511c' = 'YubiKey 5 NFC / 5C NFC (fw 5.7, FIDO L2)'
            'd7781e5d-e353-46aa-afe2-3ca49f13332a' = 'YubiKey 5 NFC / 5C NFC (fw 5.7, FIDO L2)'
            'f4ce5fc0-57d3-46f5-a736-efb7d5bc63b5' = 'YubiKey 5 NFC / 5C NFC (fw 5.8, FIDO L2)'
            '662ef48a-95e2-4aaa-a6c1-5b9c40375824' = 'YubiKey 5 NFC / 5C NFC - Enhanced PIN (fw 5.7, FIDO L2)'
            '19083c3d-8383-4b18-bc03-8f1c9ab2fd1b' = 'YubiKey 5 Nano / 5C Nano / 5C (fw 5.7, FIDO L2)'
            'ff4dac45-ede8-4ec2-aced-cf66103f4335' = 'YubiKey 5 Nano / 5C Nano / 5C (fw 5.7, FIDO L2)'
            '0a357157-9b18-4c8a-920e-d156e972b2f8' = 'YubiKey 5 Nano / 5C Nano / 5C (fw 5.8, FIDO L2)'
            'c5ef55ff-ad9a-4b9f-b580-adebafe026d0' = 'YubiKey 5Ci / 5Ci CSPN (fw 5.2-5.4, FIDO L1)'
            'a02167b9-ae71-4ac7-9a07-06432ebb6f1c' = 'YubiKey 5Ci (fw 5.7, FIDO L2)'
            '24673149-6c86-42e7-98d9-433fb5b73296' = 'YubiKey 5Ci (fw 5.7, FIDO L2)'
            '03012cb7-4fb2-42e7-9e8d-a81f10e2a5e9' = 'YubiKey 5Ci (fw 5.8, FIDO L2)'
            '3aa78eb1-ddd8-46a8-a821-8f8ec57a7bd5' = 'YubiKey 5 CCN Series with NFC (fw 5.7, FIDO L2)'
            'eb7ef748-cbe0-4b40-b8f6-07bd2d592d35' = 'YubiKey 5 CCN Series with NFC (fw 5.8, FIDO L2)'
            'c1f9a0bc-1dd2-404a-b27f-8e29047a43fd' = 'YubiKey 5 NFC FIPS / 5C NFC FIPS - FIPS 140-2 (fw 5.4, FIDO L2)'
            '73bb0cd4-e502-49b8-9c6f-b59445bf720b' = 'YubiKey 5 Nano FIPS / 5C Nano FIPS / 5C FIPS - FIPS 140-2 (fw 5.4, FIDO L2)'
            '85203421-48f9-4355-9bc8-8a53846e5083' = 'YubiKey 5Ci FIPS - FIPS 140-2 (fw 5.4, FIDO L2)'
            'fcc0118f-cd45-435b-8da1-9782b2da0715' = 'YubiKey 5 NFC FIPS / 5C NFC FIPS - FIPS 140-3 (fw 5.7, FIDO L2)'
            '57f7de54-c807-4eab-b1c6-1c9be7984e92' = 'YubiKey 5 Nano FIPS / 5C Nano FIPS / 5C FIPS - FIPS 140-3 (fw 5.7, FIDO L2)'
            '7b96457d-e3cd-432b-9ceb-c9fdd7ef7432' = 'YubiKey 5Ci FIPS - FIPS 140-3 (fw 5.7, FIDO L2)'
            'd8522d9f-575b-4866-88a9-ba99fa02f35b' = 'YubiKey Bio - FIDO Edition (fw 5.5-5.6, FIDO L1)'
            'dd86a2da-86a0-4cbe-b462-4bd31f57bc6f' = 'YubiKey Bio - FIDO Edition (fw 5.7, FIDO L2)'
            '7409272d-1ff9-4e10-9fc9-ac0019c124fd' = 'YubiKey Bio - FIDO Edition (fw 5.7, FIDO L2)'
            '9dd8d593-2213-438a-97f8-d6b813d51c27' = 'YubiKey Bio - FIDO Edition (fw 5.8, FIDO L2)'
            '7d1351a6-e097-4852-b8bf-c9ac5c9ce4a3' = 'YubiKey Bio Series - Multi-protocol Edition (fw 5.6, FIDO L1)'
            '90636e1f-ef82-43bf-bdcf-5255f139d12f' = 'YubiKey Bio Series - Multi-protocol Edition (fw 5.7, FIDO L2)'
            '34744913-4f57-4e6e-a527-e9ec3c4b94e6' = 'YubiKey Bio Series - Multi-protocol Edition (fw 5.7, FIDO L2)'
            'ba0a9266-40d8-4048-9786-d710b5474752' = 'YubiKey Bio Series - Multi-protocol Edition (fw 5.8, FIDO L2)'
            'f8a011f3-8c0a-4d15-8006-17111f9edc7d' = 'Security Key by Yubico (Blue) (fw 5.1, FIDO L1)'
            'b92c3f9a-c014-4056-887f-140a2501163b' = 'Security Key by Yubico (Blue) (fw 5.2, FIDO L1)'
            '6d44ba9b-f6ec-2e49-b930-0c8fe920cb73' = 'Security Key NFC (Blue) (fw 5.1, FIDO L1)'
            '149a2021-8ef6-4133-96b8-81f8d5b7f1f5' = 'Security Key NFC (Blue) (fw 5.2-5.4, FIDO L1)'
            'a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa' = 'Security Key NFC (Black) (fw 5.4, FIDO L2)'
            'e77e3c64-05e3-428b-8824-0cbeb04b829d' = 'Security Key NFC (Black) (fw 5.7, FIDO L2)'
            'b7d3f68e-88a6-471e-9ecf-2df26d041ede' = 'Security Key NFC (Black) (fw 5.7, FIDO L2)'
            '0f083f18-4105-43a8-ad69-24e812e38141' = 'Security Key NFC (Black) (fw 5.8, FIDO L2)'
            '0bb43545-fd2c-4185-87dd-feb0b2916ace' = 'Security Key NFC - Enterprise Edition (fw 5.4, FIDO L2)'
            '47ab2fb4-66ac-4184-9ae1-86be814012d5' = 'Security Key NFC - Enterprise Edition (fw 5.7, FIDO L2)'
            'ed042a3a-4b22-4455-bb69-a267b652ae7e' = 'Security Key NFC - Enterprise Edition (fw 5.7, FIDO L2)'
            '24083bcb-3034-4867-99de-a3b52e1d426a' = 'Security Key NFC - Enterprise Edition (fw 5.8, FIDO L2)'
            '1ac71f64-468d-4fe0-bef1-0e5f2f551f18' = 'YubiKey 5 NFC / 5C NFC - enterprise attestation (fw 5.7, FIDO L2)'
            '6ab56fad-881f-4a43-acb2-0be065924522' = 'YubiKey 5 NFC / 5C NFC - enterprise attestation (fw 5.7, FIDO L2)'
            '41e39911-c669-4811-b860-c6ad0b411b96' = 'YubiKey 5 NFC / 5C NFC - enterprise attestation (fw 5.8, FIDO L2)'
            'b2c1a50b-dad8-4dc7-ba4d-0ce9597904bc' = 'YubiKey 5 NFC / 5C NFC - Enhanced PIN, enterprise attestation (fw 5.7, FIDO L2)'
            '9a3f2abd-a73d-439c-9ee7-1b53a857eaa7' = 'YubiKey 5 NFC / 5C NFC - Enhanced PIN, enterprise attestation (fw 5.8, FIDO L2)'
            '20ac7a17-c814-4833-93fe-539f0d5e3389' = 'YubiKey 5 Nano / 5C Nano / 5C - enterprise attestation (fw 5.7, FIDO L2)'
            '4599062e-6926-4fe7-9566-9e8fb1aedaa0' = 'YubiKey 5 Nano / 5C Nano / 5C - enterprise attestation (fw 5.7, FIDO L2)'
            '524de2de-982f-49b4-a769-2b5e3b73ad79' = 'YubiKey 5 Nano / 5C Nano / 5C - enterprise attestation (fw 5.8, FIDO L2)'
            'b90e7dc1-316e-4fee-a25a-56a666a670fe' = 'YubiKey 5Ci - enterprise attestation (fw 5.7, FIDO L2)'
            '3b24bf49-1d45-4484-a917-13175df0867b' = 'YubiKey 5Ci - enterprise attestation (fw 5.7, FIDO L2)'
            'c3479970-e58a-4f70-836f-853bf42fb063' = 'YubiKey 5Ci - enterprise attestation (fw 5.8, FIDO L2)'
            '4fc84f16-2545-4e53-b8fc-7bf4d7282a10' = 'YubiKey 5 CCN Series with NFC - enterprise attestation (fw 5.7, FIDO L2)'
            '3ec9c8d3-a5a7-415b-a7b5-f1d606368d3f' = 'YubiKey 5 CCN Series with NFC - enterprise attestation (fw 5.8, FIDO L2)'
            '79f3c8ba-9e35-484b-8f47-53a5a0f5c630' = 'YubiKey 5 NFC FIPS / 5C NFC FIPS - FIPS 140-3, enterprise attestation (fw 5.7, FIDO L2)'
            '905b4cb4-ed6f-4da9-92fc-45e0d4e9b5c7' = 'YubiKey 5 Nano FIPS / 5C Nano FIPS / 5C FIPS - FIPS 140-3, enterprise attestation (fw 5.7, FIDO L2)'
            '3a662962-c6d4-4023-bebb-98ae92e78e20' = 'YubiKey 5Ci FIPS - FIPS 140-3, enterprise attestation (fw 5.7, FIDO L2)'
            '83c47309-aabb-4108-8470-8be838b573cb' = 'YubiKey Bio Series - FIDO Edition, enterprise attestation (fw 5.6, FIDO L1)'
            '8c39ee86-7f9a-4a95-9ba3-f6b097e5c2ee' = 'YubiKey Bio Series - FIDO Edition, enterprise attestation (fw 5.7, FIDO L2)'
            'ad08c78a-4e41-49b9-86a2-ac15b06899e2' = 'YubiKey Bio Series - FIDO Edition, enterprise attestation (fw 5.7, FIDO L2)'
            'add92433-0d69-4026-8166-29b25bce64e9' = 'YubiKey Bio Series - FIDO Edition, enterprise attestation (fw 5.8, FIDO L2)'
            '97e6a830-c952-4740-95fc-7c78dc97ce47' = 'YubiKey Bio Series - Multi-protocol Edition, enterprise attestation (fw 5.7, FIDO L2)'
            '6ec5cff2-a0f9-4169-945b-f33b563f7b99' = 'YubiKey Bio Series - Multi-protocol Edition, enterprise attestation (fw 5.7, FIDO L2)'
            'dc5e949d-f939-43b3-9877-a85c7186b753' = 'YubiKey Bio Series - Multi-protocol Edition, enterprise attestation (fw 5.8, FIDO L2)'
            '9ff4cc65-6154-4fff-ba09-9e2af7882ad2' = 'Security Key NFC - Enterprise Edition, enterprise attestation (fw 5.7, FIDO L2)'
            '72c6b72d-8512-4c66-8359-9d3d10d9222f' = 'Security Key NFC - Enterprise Edition, enterprise attestation (fw 5.7, FIDO L2)'
            'ab7d1767-3fa0-4388-b6c4-feef7a844809' = 'Security Key NFC - Enterprise Edition, enterprise attestation (fw 5.8, FIDO L2)'

            # Synced-passkey providers, same reference list ConvertTo-SAWNormalizedPasskeys uses
            # (https://github.com/passkeydeveloper/passkey-authenticator-aaguids) - combined here
            # so this single lookup covers both hardware keys and passkey providers.
            'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' = 'Google Password Manager (synced passkey)'
            'dd4ec289-e01d-41c9-bb89-70fa845d4bf2' = 'iCloud Keychain (Managed) (synced passkey)'
            'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' = 'Apple Passwords / iCloud Keychain (synced passkey)'
            '531126d6-e717-415c-9320-3d9aa6981239' = 'Dashlane (synced passkey)'
            'bada5566-a7aa-401f-bd96-45619a55120d' = '1Password (synced passkey)'
            'b84e4048-15dc-4dd0-8640-f4f60813c8af' = 'NordPass (synced passkey)'
            '0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6' = 'Keeper (synced passkey)'
            '891494da-2c90-4d31-a9cd-4eab0aed1309' = 'Sesame (synced passkey)'
            'f3809540-7f14-49c1-a8b3-8f813b225541' = 'Enpass (synced passkey)'
            'd548826e-79b4-db40-a3d8-11116f7e8349' = 'Bitwarden (synced passkey)'
            '53414d53-554e-4700-0000-000000000000' = 'Samsung Pass (synced passkey)'
        }
    }

    process {
        if ($RawConfig.state -ne 'enabled') {
            # Same "not applicable" boundary ConvertTo-SAWNormalizedPasskeys uses for
            # PASS001-003: key restrictions configured while FIDO2 itself is tenant-wide
            # disabled aren't currently enforcing anything, so there's nothing to list.
            Write-Verbose "ConvertTo-SAWFido2KeyInventory: FIDO2 is not enabled tenant-wide (state: $($RawConfig.state)); key inventory is not applicable"
            return $null
        }

        $isEnforced = [bool]$RawConfig.keyRestrictions.isEnforced
        $enforcementType = $RawConfig.keyRestrictions.enforcementType
        $configuredAaGuids = @($RawConfig.keyRestrictions.aaGuids) | Where-Object { $_ }

        $keys = foreach ($aaguid in $configuredAaGuids) {
            $known = $knownFido2KeyAaguids[$aaguid.ToLowerInvariant()]
            @{
                Aaguid     = $aaguid
                KnownName  = if ($known) { $known } else { 'Unrecognized AAGUID - not in this toolkit''s reference list (Yubico hardware keys and common synced-passkey providers only). Check the FIDO Alliance Metadata Service or the key vendor directly.' }
                Recognized = [bool]$known
            }
        }

        $enforcementSummary = 'Not enforced - any FIDO2-compliant key or passkey provider is accepted.'
        if ($isEnforced -and $enforcementType -eq 'allow') {
            $enforcementSummary = "Allow-list: only the $($configuredAaGuids.Count) key(s)/provider(s) below may register. Anything else is rejected."
        }
        elseif ($isEnforced -and $enforcementType -eq 'block') {
            $enforcementSummary = "Block-list: every key/provider EXCEPT the $($configuredAaGuids.Count) below may register."
        }

        @{
            IsEnforced          = $isEnforced
            EnforcementType     = $enforcementType
            EnforcementSummary  = $enforcementSummary
            AllowedKeys         = @($keys)
        }
    }
}
