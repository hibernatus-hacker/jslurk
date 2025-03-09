# JSLurk

JSLurk - A tool for analysing javascript files.

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
```

