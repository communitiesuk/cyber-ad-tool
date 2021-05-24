function Get-PodeLoggingTerminalMethod
{
    return {
        param($item, $options)

        if ($PodeContext.Server.Quiet) {
            return
        }

        # check if it's an array from batching
        if ($item -is [array]) {
            $item = ($item -join [System.Environment]::NewLine)
        }

        # protect then write
        $item = ($item | Protect-PodeLogItem)
        $item.ToString() | Out-PodeHost
    }
}

function Get-PodeLoggingFileMethod
{
    return {
        param($item, $options)

        # check if it's an array from batching
        if ($item -is [array]) {
            $item = ($item -join [System.Environment]::NewLine)
        }

        # mask values
        $item = ($item | Protect-PodeLogItem)

        # variables
        $date = [DateTime]::Now.ToString('yyyy-MM-dd')

        # do we need to reset the fileId?
        if ($options.Date -ine $date) {
            $options.Date = $date
            $options.FileId = 0
        }

        # get the fileId
        if ($options.FileId -eq 0) {
            $path = (Join-Path $options.Path "$($options.Name)_$($date)_*.log")
            $options.FileId = (@(Get-ChildItem -Path $path)).Length
            if ($options.FileId -eq 0) {
                $options.FileId = 1
            }
        }

        $id = "$($options.FileId)".PadLeft(3, '0')
        if ($options.MaxSize -gt 0) {
            $path = (Join-Path $options.Path "$($options.Name)_$($date)_$($id).log")
            if ((Get-Item -Path $path -Force).Length -ge $options.MaxSize) {
                $options.FileId++
                $id = "$($options.FileId)".PadLeft(3, '0')
            }
        }

        # get the file to write to
        $path = (Join-Path $options.Path "$($options.Name)_$($date)_$($id).log")

        # write the item to the file
        $item.ToString() | Out-File -FilePath $path -Encoding utf8 -Append -Force

        # if set, remove log files beyond days set (ensure this is only run once a day)
        if (($options.MaxDays -gt 0) -and ($options.NextClearDown -lt [DateTime]::Now.Date)) {
            $date = [DateTime]::Now.Date.AddDays(-$options.MaxDays)

            Get-ChildItem -Path $options.Path -Filter '*.log' -Force |
                Where-Object { $_.CreationTime -lt $date } |
                Remove-Item $_ -Force | Out-Null

            $options.NextClearDown = [DateTime]::Now.Date.AddDays(1)
        }
    }
}

function Get-PodeLoggingInbuiltType
{
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet('Errors', 'Requests')]
        [string]
        $Type
    )

    switch ($Type.ToLowerInvariant())
    {
        'requests' {
            $script = {
                param($item, $options)

                # just return the item if Raw is set
                if ($options.Raw) {
                    return $item
                }

                function sg($value) {
                    if ([string]::IsNullOrWhiteSpace($value)) {
                        return '-'
                    }

                    return $value
                }

                # build the url with http method
                $url = "$(sg $item.Request.Method) $(sg $item.Request.Resource) $(sg $item.Request.Protocol)"

                # build and return the request row
                return "$(sg $item.Host) $(sg $item.RfcUserIdentity) $(sg $item.User) [$(sg $item.Date)] `"$($url)`" $(sg $item.Response.StatusCode) $(sg $item.Response.Size) `"$(sg $item.Request.Referrer)`" `"$(sg $item.Request.Agent)`""
            }
        }

        'errors' {
            $script = {
                param($item, $options)

                # do nothing if the error level isn't present
                if (@($options.Levels) -inotcontains $item.Level) {
                    return
                }

                # just return the item if Raw is set
                if ($options.Raw) {
                    return $item
                }

                # build the exception details
                $row = @(
                    "Date: $($item.Date.ToString('yyyy-MM-dd HH:mm:ss'))",
                    "Level: $($item.Level)",
                    "ThreadId: $($item.ThreadId)",
                    "Server: $($item.Server)",
                    "Category: $($item.Category)",
                    "Message: $($item.Message)",
                    "StackTrace: $($item.StackTrace)"
                )

                # join the details and return
                return "$($row -join "`n")`n"
            }
        }
    }

    return $script
}

function Get-PodeRequestLoggingName
{
    return '__pode_log_requests__'
}

function Get-PodeErrorLoggingName
{
    return '__pode_log_errors__'
}

function Get-PodeLogger
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return $PodeContext.Server.Logging.Types[$Name]
}

function Test-PodeLoggerEnabled
{
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $Name
    )

    return ($PodeContext.Server.Logging.Enabled -and $PodeContext.Server.Logging.Types.ContainsKey($Name))
}

function Test-PodeErrorLoggingEnabled
{
    return (Test-PodeLoggerEnabled -Name (Get-PodeErrorLoggingName))
}

function Test-PodeRequestLoggingEnabled
{
    return (Test-PodeLoggerEnabled -Name (Get-PodeRequestLoggingName))
}

function Write-PodeRequestLog
{
    param (
        [Parameter(Mandatory=$true)]
        $Request,

        [Parameter(Mandatory=$true)]
        $Response,

        [Parameter()]
        [string]
        $Path
    )

    # do nothing if logging is disabled, or request logging isn't setup
    $name = Get-PodeRequestLoggingName
    if (!(Test-PodeLoggerEnabled -Name $name)) {
        return
    }

    # build a request object
    $item = @{
        Host = $Request.RemoteEndPoint.Address.IPAddressToString
        RfcUserIdentity = '-'
        User = '-'
        Date = [DateTime]::Now.ToString('dd/MMM/yyyy:HH:mm:ss zzz')
        Request = @{
            Method = $Request.HttpMethod.ToUpperInvariant()
            Resource = $Path
            Protocol = "HTTP/$($Request.ProtocolVersion)"
            Referrer = $Request.UrlReferrer
            Agent = $Request.UserAgent
        }
        Response = @{
            StatusCode = $Response.StatusCode
            StatusDescription = $Response.StatusDescription
            Size = '-'
        }
    }

    if ($Response.ContentLength64 -gt 0) {
        $item.Response.Size = $Response.ContentLength64
    }

    # add the item to be processed
    $PodeContext.LogsToProcess.Add(@{
        Name = $name
        Item = $item
    }) | Out-Null
}

function Add-PodeRequestLogEndware
{
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $WebEvent
    )

    # do nothing if logging is disabled, or request logging isn't setup
    $name = Get-PodeRequestLoggingName
    if (!(Test-PodeLoggerEnabled -Name $name)) {
        return
    }

    # add the request logging endware
    $WebEvent.OnEnd += @{
        Logic = {
            Write-PodeRequestLog -Request $WebEvent.Request -Response $WebEvent.Response -Path $WebEvent.Path
        }
    }
}

function Start-PodeLoggingRunspace
{
    # skip if there are no loggers configured, or logging is disabled
    if (($PodeContext.Server.Logging.Types.Count -eq 0) -or (!$PodeContext.Server.Logging.Enabled)) {
        return
    }

    $script = {
        while ($true)
        {
            # if there are no logs to process, just sleep for a few seconds - but after checking the batch
            if ($PodeContext.LogsToProcess.Count -eq 0) {
                Test-PodeLoggerBatches
                Start-Sleep -Seconds 5
                continue
            }

            # safely pop off the first log from the array
            $log = (Lock-PodeObject -Return -Object $PodeContext.LogsToProcess -ScriptBlock {
                $log = $PodeContext.LogsToProcess[0]
                $PodeContext.LogsToProcess.RemoveAt(0) | Out-Null
                return $log
            })

            # run the log item through the appropriate method
            $logger = Get-PodeLogger -Name $log.Name
            $now = [datetime]::Now

            # if the log is null, check batch then sleep and skip
            if ($null -eq $log) {
                Start-Sleep -Milliseconds 100
                continue
            }

            # convert to log item into a writable format
            $_args = @($log.Item) + @($logger.Arguments)
            if ($null -ne $logger.UsingVariables) {
                $_vars = @()
                foreach ($_var in $logger.UsingVariables) {
                    $_vars += ,$_var.Value
                }
                $_args = $_vars + $_args
            }

            $result = @(Invoke-PodeScriptBlock -ScriptBlock $logger.ScriptBlock -Arguments $_args -Return -Splat)

            # check batching
            $batch = $logger.Method.Batch
            if ($batch.Size -gt 1) {
                # add current item to batch
                $batch.Items += $result
                $batch.LastUpdate = $now

                # if the current amount of items matches the batch, write
                $result = $null
                if ($batch.Items.Length -ge $batch.Size) {
                    $result = $batch.Items
                }

                # if we're writing, reset the items
                if ($null -ne $result) {
                    $batch.Items = @()
                }
            }

            # send the writable log item off to the log writer
            if ($null -ne $result) {
                $_args = @(,$result) + @($logger.Method.Arguments)
                if ($null -ne $logger.Method.UsingVariables) {
                    $_vars = @()
                    foreach ($_var in $logger.Method.UsingVariables) {
                        $_vars += ,$_var.Value
                    }
                    $_args = $_vars + $_args
                }

                Invoke-PodeScriptBlock -ScriptBlock $logger.Method.ScriptBlock -Arguments $_args -Splat
            }

            # small sleep to lower cpu usage
            Start-Sleep -Milliseconds 100
        }
    }

    Add-PodeRunspace -Type Main -ScriptBlock $script
}

function Test-PodeLoggerBatches
{
    $now = [datetime]::Now

    # check each logger, and see if its batch needs to be written
    foreach ($logger in $PodeContext.Server.Logging.Types.Values)
    {
        $batch = $logger.Method.Batch
        if (($batch.Size -gt 1) -and ($batch.Items.Length -gt 0) -and
            ($batch.Timeout -gt 0) -and ($null -ne $batch.LastUpdate) -and ($batch.LastUpdate.AddSeconds($batch.Timeout) -le $now))
        {
            $result = $batch.Items
            $batch.Items = @()

            $_args = @(,$result) + @($logger.Method.Arguments)
            if ($null -ne $logger.Method.UsingVariables) {
                $_vars = @()
                foreach ($_var in $logger.Method.UsingVariables) {
                    $_vars += ,$_var.Value
                }
                $_args = $_vars + $_args
            }

            Invoke-PodeScriptBlock -ScriptBlock $logger.Method.ScriptBlock -Arguments $_args -Splat
        }
    }
}