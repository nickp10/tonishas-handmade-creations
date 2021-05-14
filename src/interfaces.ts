import { ObjectID } from "bson";

export interface IClientAppState {
    hasAdminAccount: boolean;
    isLoggedIn: boolean;
    serverError: string;
}

export interface IUser {
    _id?: ObjectID;
    username?: string;
    password?: string;
}
