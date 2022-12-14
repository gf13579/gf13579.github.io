---
title: "Building a Basic Reporting Page With Material Reacte Table"
date: 2022-12-26T19:53:28+10:00
draft: true
---

I wanted to build a basic modern website with tables that presented data from a SQL(ite)-based backend.

After looking into the most popular front-end frameworks I settled on using React and [Material React Table](https://www.material-react-table.com/), a component built with Material UI (v5) and TanStack Table (v8). I also explored the Next.js framework for hosting the application.

With minimal JS experience I chose to work through tutorials to stand up a proof-of-concept that presents table-based views on my SQL database:

- [Tutorial: Intro to React - reactjs.org](https://reactjs.org/tutorial/tutorial.html#setup-option-2-local-development-environment)
- [Create React App](https://create-react-app.dev/)
- [axios](https://github.com/axios/axios) for backend access
- [Material UI - Overview](https://mui.com/material-ui/getting-started/overview/)

- [Usage - material-react-table.com](https://www.material-react-table.com/docs/getting-started/usage)
- [Basic Example - material-react-table.com](https://www.material-react-table.com/docs/examples/basic)
- [Create a Next.js App  - nextjs.org](https://nextjs.org/learn/basics/create-nextjs-app)

## Steps taken

The following is a summary of the steps taken.

### Install Node

```bash

# Download the latest LTS release of Node from https://nodejs.org/en/download/
# wget 'https://nodejs.org/dist/v18.12.1/node-v18.12.1-linux-x64.tar.xz'
# tar -xf node-v18.12.1-linux-x64.tar.xz

# From https://github.com/nodesource/distributions/blob/master/README.md, linked from https://nodejs.org/en/download/
curl -fsSL https://deb.nodesource.com/setup_19.x | sudo -E bash - &&\
sudo apt-get install -y nodejs
```

Install `yarn` as an `npm` replacement:

```bash
sudo npm install --global yarn
```

### Create a React App

Creating applications `amashup-app`:

```bash
# From https://reactjs.org/tutorial/tutorial.html#setup-option-2-local-development-environment
npx create-react-app amashup-app

cd my-app
cd src
rm -f *

```

Create index.css and index.js using the content provided by the tutorial, then add the following to the top of index.js:

```js
import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
```



## Attempt 2

With yarn from the outset:

```bash
yarn create react-app amashup-app
yarn start
```

Running `npm start` from the terminal within VS Code starts node on port 3000, forwards the port over SSH and launches a local browser pointing at http://localhost:3000/.

## Material UI

> Material UI and MUI Base feature many of the same UI components, but MUI Base comes without any default styles or styling solutions.
> 
> Material UI is comprehensive in that it comes packaged with default styles, and is optimized to work with Emotion (or styled-components).
> 
> MUI Base, by contrast, could be considered the "skeletal" or "headless" counterpart to Material UI???in fact, Material UI v6 will use MUI Base components and hooks for its foundational structure.

Add Material UI to the project:

```bash
cd ~/amashup-app
yarn add @mui/material @emotion/react @emotion/styled
```
Note - I potentially should've used `npm`, noting this warning:

> warning package-lock.json found. Your project contains lock files generated by tools other than Yarn. It is advised not to mix package managers in order to avoid resolution inconsistencies caused by unsynchronized lock files. To clear this warning, remove package-lock.json.

After the Material UI installation I have 820+ directories in node_modules.

I can start my site using `npm start` or `yarn start`.

Adding the `roboto` font:

```bash
yarn add @fontsource/roboto
```

And the following to index.js:

```js
import '@fontsource/roboto/300.css';
import '@fontsource/roboto/400.css';
import '@fontsource/roboto/500.css';
import '@fontsource/roboto/700.css';
```

For icons:

```bash
yarn add @mui/icons-material
```


## Next steps

- Get a MUI page up and running - maybe this? - https://github.com/mui/material-ui/tree/master/examples/create-react-app
- get a material-react-table up and running using the tutorial code
- Continue reading https://reactjs.org/tutorial/tutorial.html#what-is-react
- connect it to my backend (via axios? - https://create-react-app.dev/docs/fetching-data-with-ajax-requests)
- get a pretty admin dashboard template working