This is a shell script that works around the issue with sm64plus on linux that causes black and purple textures

You need to run sm64plus first atleast once!

Inorder to be run from the sm64plus launcher the script must be an executable

To do this you must have shc installed and run the following command:

shc -r -f /path/to/sm64.us.sh

This will compile the script into c code aswell as provide an executable binary

Copy the original sm64.us exectubale in "/build/us_pc/" to ~/.config/sm64plus/ and rename it to sm64

Rename the original sm64.us to sm64.us.bak and rename the one you generated to sm64.us and place it in there.

Now copy the gfx folder to ~/.config/sm64plus and you should be all set!
