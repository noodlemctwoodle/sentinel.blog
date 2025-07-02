#requires -version 2

<#
.SYNOPSIS
Calculate a list on IP addresses from a Subnet (/16)

.DESCRIPTION
Use this script to calculate IP addresses from a Subnet that can be used to in a Sentinel Watchlist

.EXAMPLE
$Results = .\Create-IPWatchlistFromSubnet -NetworkAddress '192.168.0.10 255.255.255.0' -Enumerate
$Results = .\Create-IPWatchlistFromSubnet -NetworkAddress '192.168.0.0/24' -Enumerate
$Results.IPEnumerated
$Results.IPEnumerated | Out-File "C:\PathToFile\NameofFile.csv" - NoClobber

.OUTPUTS
Example:
    192.168.0.1
    192.168.0.2
    192.168.0.3
    192.168.0.4
    192.168.0.5
    192.168.0.6

.NOTES
  Version:          0.1
  Author:           noodlemctwoodle
  Creation Date:    14/07/2021
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)][string[]] $NetworkAddress,
    [string] $Contains,
    [switch] $Enumerate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$IPv4Regex = '(?:(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)\.){3}(?:0?0?\d|0?[1-9]\d|1\d\d|2[0-5][0-5]|2[0-4]\d)'

function Convert-IPToBinary
{
    param(
        [string] $IP
    )
    $IP = $IP.Trim()
    if ($IP -match "\A${IPv4Regex}\z")
    {
        try
        {
            return ($IP.Split('.') | ForEach-Object { [System.Convert]::ToString([byte] $_, 2).PadLeft(8, '0') }) -join ''
        }
        catch
        {
            Write-Warning -Message "Error converting '$IP' to a binary string: $_"
            return $Null
        }
    }
    else
    {
        Write-Warning -Message "Invalid IP detected: '$IP'."
        return $Null
    }
}

function Convert-BinaryToIP
{
    param(
        [string] $Binary
    )
    $Binary = $Binary -replace '\s+'
    if ($Binary.Length % 8)
    {
        Write-Warning -Message "Binary string '$Binary' is not evenly divisible by 8."
        return $Null
    }
    [int] $NumberOfBytes = $Binary.Length / 8
    $Bytes = @(foreach ($i in 0..($NumberOfBytes-1))
    {
        try
        {
            [System.Convert]::ToByte($Binary.Substring(($i * 8), 8), 2)
        }
        catch
        {
            Write-Warning -Message "Error converting '$Binary' to bytes. `$i was $i."
            return $Null
        }
    })
    return $Bytes -join '.'
}

function Get-ProperCIDR
{
    param(
        [string] $CIDRString
    )
    $CIDRString = $CIDRString.Trim()
    $o = '' | Select-Object -Property IP, NetworkLength
    if ($CIDRString -match "\A(?<IP>${IPv4Regex})\s*/\s*(?<NetworkLength>\d{1,2})\z")
    {
        if ([int] $Matches['NetworkLength'] -lt 0 -or [int] $Matches['NetworkLength'] -gt 32)
        {
            Write-Warning "Network length out of range (0-32) in CIDR string: '$CIDRString'."
            return
        }
        $o.IP = $Matches['IP']
        $o.NetworkLength = $Matches['NetworkLength']
    }
    elseif ($CIDRString -match "\A(?<IP>${IPv4Regex})[\s/]+(?<SubnetMask>${IPv4Regex})\z")
    {
        $o.IP = $Matches['IP']
        $SubnetMask = $Matches['SubnetMask']
        if (-not ($BinarySubnetMask = Convert-IPToBinary $SubnetMask))
        {
            return
        }
        if ((($BinarySubnetMask) -replace '\A1+') -match '1')
        {
            Write-Warning -Message "Invalid subnet mask in CIDR string '$CIDRString'. Subnet mask: '$SubnetMask'."
            return
        }
        $o.NetworkLength = [regex]::Matches($BinarySubnetMask, '1').Count
    }
    else
    {
        Write-Warning -Message "Invalid CIDR string: '${CIDRString}'. Valid examples: '192.168.1.0/24', '10.0.0.0/255.0.0.0'."
        return
    }
    if ($o.IP -match '\A(?:(?:1\.){3}1|(?:0\.){3}0)\z')
    {
        Write-Warning "Invalid IP detected in CIDR string '${CIDRString}': '$($o.IP)'. An IP can not be all ones or all zeroes."
        return
    }
    return $o
}

function Get-IPRange
{
    param(
        [string] $StartBinary,
        [string] $EndBinary
    )
    $StartIPArray = @((Convert-BinaryToIP $StartBinary) -split '\.')
    $EndIPArray = ((Convert-BinaryToIP $EndBinary) -split '\.')
    Write-Verbose -Message "Start IP: $($StartIPArray -join '.')"
    Write-Verbose -Message "End IP: $($EndIPArray -join '.')"
    $FirstOctetArray = @($StartIPArray[0]..$EndIPArray[0])
    $SecondOctetArray = @($StartIPArray[1]..$EndIPArray[1])
    $ThirdOctetArray = @($StartIPArray[2]..$EndIPArray[2])
    $FourthOctetArray = @($StartIPArray[3]..$EndIPArray[3])
    $IPs = @(foreach ($First in $FirstOctetArray)
    {
        foreach ($Second in $SecondOctetArray)
        {
            foreach ($Third in $ThirdOctetArray)
            {
                foreach ($Fourth in $FourthOctetArray)
                {
                    "$First.$Second.$Third.$Fourth"
                }
            }
        }
    })
    $IPs = $IPs | Sort-Object -Unique -Property @{Expression={($_ -split '\.' | ForEach-Object { '{0:D3}' -f [int]$_ }) -join '.' }}
    return $IPs
}

function Get-IPRange2
{
    param(
        [string] $StartBinary,
        [string] $EndBinary
    )
    [int64] $StartInt = [System.Convert]::ToInt64($StartBinary, 2)
    [int64] $EndInt = [System.Convert]::ToInt64($EndBinary, 2)
    for ($BinaryIP = $StartInt; $BinaryIP -le $EndInt; $BinaryIP++)
    {
        Convert-BinaryToIP ([System.Convert]::ToString($BinaryIP, 2).PadLeft(32, '0'))
    }
}

function Test-IPIsInNetwork {
    param(
        [string] $IP,
        [string] $StartBinary,
        [string] $EndBinary
    )
    $TestIPBinary = Convert-IPToBinary $IP
    [int64] $TestIPInt64 = [System.Convert]::ToInt64($TestIPBinary, 2)
    [int64] $StartInt64 = [System.Convert]::ToInt64($StartBinary, 2)
    [int64] $EndInt64 = [System.Convert]::ToInt64($EndBinary, 2)
    if ($TestIPInt64 -ge $StartInt64 -and $TestIPInt64 -le $EndInt64)
    {
        return $True
    }
    else
    {
        return $False
    }
}

function Get-NetworkInformationFromProperCIDR
{
    param(
        [psobject] $CIDRObject
    )
    $o = '' | Select-Object -Property IP, NetworkLength, SubnetMask, NetworkAddress, HostMin, HostMax, 
        Broadcast, UsableHosts, TotalHosts, IPEnumerated, BinaryIP, BinarySubnetMask, BinaryNetworkAddress,
        BinaryBroadcast
    $o.IP = [string] $CIDRObject.IP
    $o.BinaryIP = Convert-IPToBinary $o.IP
    $o.NetworkLength = [int32] $CIDRObject.NetworkLength
    $o.SubnetMask = Convert-BinaryToIP ('1' * $o.NetworkLength).PadRight(32, '0')
    $o.BinarySubnetMask = ('1' * $o.NetworkLength).PadRight(32, '0')
    $o.BinaryNetworkAddress = $o.BinaryIP.SubString(0, $o.NetworkLength).PadRight(32, '0')
    if ($Contains)
    {
        if ($Contains -match "\A${IPv4Regex}\z")
        {
            return Test-IPIsInNetwork $Contains $o.BinaryNetworkAddress $o.BinaryNetworkAddress.SubString(0, $o.NetworkLength).PadRight(32, '1')
        }
        else
        {
            Write-Error "Invalid IPv4 address specified with -Contains"
            return
        }
    }
    $o.NetworkAddress = Convert-BinaryToIP $o.BinaryNetworkAddress
    if ($o.NetworkLength -eq 32 -or $o.NetworkLength -eq 31)
    {
        $o.HostMin = $o.IP
    }
    else
    {
        $o.HostMin = Convert-BinaryToIP ([System.Convert]::ToString(([System.Convert]::ToInt64($o.BinaryNetworkAddress, 2) + 1), 2)).PadLeft(32, '0')
    }
    [string] $BinaryBroadcastIP = $o.BinaryNetworkAddress.SubString(0, $o.NetworkLength).PadRight(32, '1')
    $o.BinaryBroadcast = $BinaryBroadcastIP
    [int64] $DecimalHostMax = [System.Convert]::ToInt64($BinaryBroadcastIP, 2) - 1
    [string] $BinaryHostMax = [System.Convert]::ToString($DecimalHostMax, 2).PadLeft(32, '0')
    $o.HostMax = Convert-BinaryToIP $BinaryHostMax
    $o.TotalHosts = [int64][System.Convert]::ToString(([System.Convert]::ToInt64($BinaryBroadcastIP, 2) - [System.Convert]::ToInt64($o.BinaryNetworkAddress, 2) + 1))
    $o.UsableHosts = $o.TotalHosts - 2
    if ($o.NetworkLength -eq 32)
    {
        $o.Broadcast = $Null
        $o.UsableHosts = [int64] 1
        $o.TotalHosts = [int64] 1
        $o.HostMax = $o.IP
    }
    elseif ($o.NetworkLength -eq 31)
    {
        $o.Broadcast = $Null
        $o.UsableHosts = [int64] 2
        $o.TotalHosts = [int64] 2
        [int64] $DecimalHostMax2 = [System.Convert]::ToInt64($BinaryBroadcastIP, 2)
        [string] $BinaryHostMax2 = [System.Convert]::ToString($DecimalHostMax2, 2).PadLeft(32, '0')
        $o.HostMax = Convert-BinaryToIP $BinaryHostMax2
    }
    elseif ($o.NetworkLength -eq 30)
    {
        $o.UsableHosts = [int64] 2
        $o.TotalHosts = [int64] 4
        $o.Broadcast = Convert-BinaryToIP $BinaryBroadcastIP
    }
    else
    {
        $o.Broadcast = Convert-BinaryToIP $BinaryBroadcastIP
    }
    if ($Enumerate)
    {
        $IPRange = @(Get-IPRange2 $o.BinaryNetworkAddress $o.BinaryNetworkAddress.SubString(0, $o.NetworkLength).PadRight(32, '1'))
        if ((31, 32) -notcontains $o.NetworkLength )
        {
            $IPRange = $IPRange[1..($IPRange.Count-1)]
            $IPRange = $IPRange[0..($IPRange.Count-2)]
        }
        $o.IPEnumerated = $IPRange
    }
    else {
        $o.IPEnumerated = @()
    }
    return $o
}

$NetworkAddress | ForEach-Object { Get-ProperCIDR $_ } | ForEach-Object { Get-NetworkInformationFromProperCIDR $_ }