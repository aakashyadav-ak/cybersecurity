JavaScript is a programming language that runs in web browsers (and servers via Node.js).

```js
// Your first JS code - displays a popup
alert("Hello, World!");

// Prints to browser console (F12 to open)
console.log("Hello, World!");
```

console.log("welcome to js"); 

## Variables
Variables are containers that store data.

#### Three Ways to Declare Variables
```js
// 1. var - old way (avoid using)
var name = "John";

// 2. let - use when value will change
let age = 25;
age = 26;  // ✅ Can reassign

// 3. const - use when value won't change
const PI = 3.14159;
PI = 3;    // ❌ Error! Cannot reassign
```

#### Naming Rules
```js
// ✅ Valid names
let userName = "John";      // camelCase (recommended)
let user_name = "John";     // snake_case
let _private = "secret";    // can start with _
let $element = "div";       // can start with $

// ❌ Invalid names
let 123abc = "error";       // cannot start with number
let my-name = "error";      // no hyphens
let let = "error";          // cannot use reserved words
```