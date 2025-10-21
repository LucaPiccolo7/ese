import { inject, Injectable } from '@angular/core';
import { HttpClient, HttpContext, HttpHeaders } from '@angular/common/http';
import { LoginRequest } from '../interface/LoginRequest';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  private httpClient = inject(HttpClient);
  private url = 'http://localhost:8080/auth';
  private httpOptions: { 
    headers: HttpHeaders,
    withCredentials: boolean,
    responseType: any
  } = {
    headers: new HttpHeaders({
      'Content-Type': 'application/x-www-form-urlencoded',
    }),
    withCredentials: true,
    responseType: 'text' as const
  };

  /*
  register(registerRequest: LoginRequest){
    const url = `${this.url}/register`;
    return this.httpClient.post(url, registerRequest, this.httpOptions);
  }
  */

  login(loginRequest: LoginRequest) {

    const url = `${this.url}/login/process`;

    const body = new URLSearchParams();
    body.set('username', loginRequest.username);
    body.set('password', loginRequest.password);

    return this.httpClient.post<string>(url, body.toString(), this.httpOptions);
  }
}
