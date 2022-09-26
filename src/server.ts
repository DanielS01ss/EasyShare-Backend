import App from "./app";
import HomeController from "./controllers/HomeController";
import bodyParser from "body-parser";

const app = new App({
    port:5000,
    controllers:[
        new HomeController()
    ],
    middleWares:[
        bodyParser.json(),
        bodyParser.urlencoded({extended:true})
    ]
})

app.listen();
