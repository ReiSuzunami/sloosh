on run argv
    if (count of argv) is not 1 then error "expected volume name"
    set volumeName to item 1 of argv

    tell application "Finder"
        tell disk volumeName
            open
            set backgroundPicture to file ".background:background.png"

            tell container window
                set current view to icon view
                set toolbar visible to false
                set statusbar visible to false
                set pathbar visible to false
                set bounds to {100, 100, 820, 540}
            end tell

            tell icon view options of container window
                set arrangement to not arranged
                set icon size to 144
                set text size to 13
                set label position to bottom
                set background picture to backgroundPicture
            end tell

            set position of item "Install Sloosh.app" to {360, 210}
            update without registering applications
            delay 2
            close
        end tell
    end tell
end run
