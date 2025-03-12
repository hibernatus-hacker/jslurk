# JSLurk

A tool for scanning javascript files for interesting tidbits.

## Installation

```sh
mix deps.get
mix escript.build
```

## Usage

```sh
./jslurk -h
./jslurk -d ./js_files.txt
cat ./js_files.txt | ./jslurk
cat ../js_files.txt | ./jslurk --download ./d --output ./out.json
./jslurk https://example.com/app.js
# your a wizard harry...
katana -em js -jc -d 5 -c 50 -silent -u https://harrypotter.com | ./jslurk
```

# Other similar tools

* jsluice
* https://github.com/cc1a2b/JShunter
* https://github.com/w9w/JSA

# Obtaining old js files

* waybackurls
* gau

## Work in progress : )

Works ok...

But it truncates results to stop huge minified JS from sneeking through but I'm going to fix this.

I'm also going to improve each module so that it returns better results.

This tool is work in progress... so come back soon : )

# Running globally

You can add the folder to your PATH for now. This will be improved in future.
