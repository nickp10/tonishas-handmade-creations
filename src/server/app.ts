import { IClientAppState, IUser } from "../interfaces";
import args from "./args";
import * as bodyParser from "body-parser";
import * as cookieParser from "cookie-parser";
import * as express from "express";
import * as jwt from "jwt-express";
import log from "./log";
import Persistence from "./persistence";
import template from "./template";
import utils from "../utils";
import { v4 as uuid4 } from "uuid";

export default class App {
    persistence: Persistence;
    static adminUsername = "admin";

    constructor() {
        this.persistence = new Persistence(args.mongoConnectionUrl, args.mongoDBName);
    }

    async startServer(): Promise<void> {
        const app = express();
        app.use(bodyParser.urlencoded({
            extended: true
        }));
        app.use(cookieParser());
        // Use a random string as the secret for the JWTs. This means JWTs will not
        // survive application restarts, but improves the security. The secret is
        // unknown until runtime and is harder to spoof a new JWT.
        app.use(jwt.init(uuid4(), {
            signOptions: {
                expiresIn: "1h"
            },
            verifyOptions: {
                ignoreExpiration: false
            }
        }));
        app.get("/", async (req, res, next) => await this.serveHome(req, res, next));
        app.use(express.static(__dirname));
        app.get("/login", async (req, res, next) => await this.serveReactClientApp(req, res, next));
        app.post("/login/json", async (req, res, next) => await this.login(req, res, next));
        app.get("/logout", async (req, res, next) => await this.logout(req, res, next));
        app.get("/changePassword", jwt.active(), async (req, res, next) => await this.serveReactClientApp(req, res, next));
        app.post("/changePassword/json", jwt.active(), async (req, res, next) => await this.changePassword(req, res, next));
        app.post("/createPassword/json", async (req, res, next) => await this.createPassword(req, res, next));
        app.use(async (err, req, res, next) => await this.handleError(err, req, res, next));
        app.listen(args.port, () => {
            log.info(`Server has started on port ${args.port}`);
        });
    }

    async serveHome(req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> {
        const jwt = req.jwt;
        if (jwt && jwt.valid) {
            res.redirect("/lineup/alternateNames/list");
        } else {
            res.redirect("/login");
        }
    }

    getJWTPayload(jwt: jwt.JWT): IClientAppState {
        if (!jwt || !jwt.valid) {
            return undefined;
        }
        return jwt.payload;
    }

    generateJWTPayload(adminUser: IUser, isLoggedIn: boolean): IClientAppState {
        return {
            hasAdminAccount: !!adminUser,
            isLoggedIn: isLoggedIn,
            serverError: undefined
        };
    }

    async generateDefaultClientAppState(): Promise<IClientAppState> {
        try {
            const adminUser = await this.persistence.users.getSingleFiltered({ username: App.adminUsername });
            return {
                hasAdminAccount: !!adminUser,
                isLoggedIn: false,
                serverError: undefined
            };
        } catch (error) {
            return {
                hasAdminAccount: false,
                isLoggedIn: false,
                serverError: error.message
            };
        }
    }

    async serveReactClientApp(req: express.Request, res: express.Response, next: express.NextFunction, title?: string): Promise<void> {
        const clientAppState = this.getJWTPayload(req.jwt) || await this.generateDefaultClientAppState();
        res.status(200).send(template(title, clientAppState));
    }

    async changePassword(req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> {
        try {
            if (!req.body.password || !req.body.confirmPassword) {
                throw { status: 401, message: "Cannot update the admin user without a password." };
            }
            if (req.body.password !== req.body.confirmPassword) {
                throw { status: 400, message: "Password and confirm password must match." };
            }
            let adminUser = await this.persistence.users.getSingleFiltered({ username: App.adminUsername});
            if (!adminUser) {
                throw { message: "The admin user has not been setup. Consider using the create password page to setup the admin user." };
            }
            if (adminUser.password !== utils.hashPassword(req.body.currentPassword)) {
                throw { status: 401, message: "Invalid current password was entered." };
            }
            adminUser.password = utils.hashPassword(req.body.password);
            await this.persistence.users.updateSingle(adminUser);
            res.sendStatus(200);
        } catch (error) {
            next(error);
        }
    }

    async createPassword(req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> {
        try {
            if (!req.body.password || !req.body.confirmPassword) {
                throw { status: 401, message: "Cannot create an admin user without a password." };
            }
            if (req.body.password !== req.body.confirmPassword) {
                throw { status: 400, message: "Password and confirm password must match." };
            }
            let adminUser = await this.persistence.users.getSingleFiltered({ username: App.adminUsername });
            if (adminUser) {
                throw { message: "The admin user has already been setup. Consider using the change password page to update the password." };
            }
            adminUser = {
                username: App.adminUsername,
                password: utils.hashPassword(req.body.password)
            };
            adminUser = await this.persistence.users.insertSingle(adminUser);
            res.jwt(this.generateJWTPayload(adminUser, true));
            res.sendStatus(200);
        } catch (error) {
            next(error);
        }
    }

    async login(req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> {
        try {
            const adminUser = await this.persistence.users.getSingleFiltered({ username: App.adminUsername });
            if (adminUser && utils.hashPassword(req.body.password) === adminUser.password) {
                res.jwt(this.generateJWTPayload(adminUser, true));
                res.sendStatus(200);
            } else {
                throw { status: 401, message: "Unable to login" };
            }
        } catch (error) {
            next(error);
        }
    }

    async logout(req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> {
        jwt.clear();
        res.redirect("/");
    }

    async handleError(err: any, req: express.Request, res: express.Response, next: express.NextFunction): Promise<void> {
        if (err.name === "JWTExpressError") {
            res.redirect("/login");
            return;
        }
        if (typeof err.status === "number") {
            res.status(err.status);
        } else {
            res.status(500);
        }
        if (typeof err === "string") {
            err = { message: err };
        } else if (err instanceof Error) {
            err = { message: err.message };
        } else if (typeof err.message === "string") {
            err = { message: err.message };
        }
        res.json(err);
    }
}