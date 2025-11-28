# ================================================================
# Quick Deployment Script for GitHub → Heroku
# ================================================================
# Run this script after reviewing DEPLOY_VIA_GITHUB.txt
# ================================================================

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Bus Tracker Server - GitHub Deployment" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check git status
Write-Host "[1/4] Checking git status..." -ForegroundColor Yellow
git status
Write-Host ""

# Step 2: Add all files
Write-Host "[2/4] Adding all files to git..." -ForegroundColor Yellow
git add .
Write-Host "✓ Files added" -ForegroundColor Green
Write-Host ""

# Step 3: Commit
Write-Host "[3/4] Committing changes..." -ForegroundColor Yellow
$commitMessage = Read-Host "Enter commit message (or press Enter for default)"
if ([string]::IsNullOrWhiteSpace($commitMessage)) {
    $commitMessage = "Prepare for Heroku deployment with all fixes"
}
git commit -m $commitMessage
Write-Host "✓ Changes committed" -ForegroundColor Green
Write-Host ""

# Step 4: Push to GitHub
Write-Host "[4/4] Pushing to GitHub..." -ForegroundColor Yellow
Write-Host "Note: If this is first time, you may need to set remote:" -ForegroundColor Gray
Write-Host "  git remote add origin https://github.com/rajatechserve/itech-bustracker-server.git" -ForegroundColor Gray
Write-Host ""

$pushChoice = Read-Host "Push to GitHub now? (y/n)"
if ($pushChoice -eq "y" -or $pushChoice -eq "Y") {
    git push origin main
    Write-Host "✓ Pushed to GitHub" -ForegroundColor Green
} else {
    Write-Host "⚠ Skipped push. Run 'git push origin main' when ready" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  Next Steps:" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "1. Go to Heroku Dashboard: https://dashboard.heroku.com" -ForegroundColor White
Write-Host "2. Click your app → Deploy tab" -ForegroundColor White
Write-Host "3. Connect to GitHub repository: itech-bustracker-server" -ForegroundColor White
Write-Host "4. Deploy the main branch" -ForegroundColor White
Write-Host "5. Set environment variables in Settings → Config Vars" -ForegroundColor White
Write-Host ""
Write-Host "Important: Set JWT_SECRET config var!" -ForegroundColor Red
Write-Host ""
Write-Host "See DEPLOY_VIA_GITHUB.txt for detailed instructions" -ForegroundColor Gray
Write-Host "================================================" -ForegroundColor Cyan
