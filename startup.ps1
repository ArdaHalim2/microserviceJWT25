param (
    [switch]$p
)

$projects = @("authservice", "gateway", "resourceserver", "jokeservice", "quoteservice")

if ($p) {
    Write-Host "Running in parallel..."

    $projects | ForEach-Object -Parallel {
        Write-Host "Building image for $_..."
        Set-Location $_
        mvn -q --no-transfer-progress spring-boot:build-image
        Set-Location ..
    }
} else {
    Write-Host "Running in sequence..."

    foreach ($project in $projects) {
        Write-Host "Building image for $project..."
        Set-Location $project
        mvn spring-boot:build-image
        Set-Location ..
    }
}
docker-compose up -d