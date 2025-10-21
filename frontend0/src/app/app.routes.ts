import { Routes } from '@angular/router';
import { Login } from './login/login';
import { Home } from './home/home';
import { Register } from './register/register';

export const routes: Routes = [
    {
        path: 'login',
        title: 'login page',
        component: Login
    },
    {
        path: 'register',
        title: 'register page',
        component: Register
    },
    {
        path: 'home',
        title: 'homepage',
        component: Home
    }
];
