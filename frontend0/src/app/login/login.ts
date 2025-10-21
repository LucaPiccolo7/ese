import { Component, inject } from '@angular/core';
import { FormGroup, FormControl, ReactiveFormsModule} from '@angular/forms';
import { Router } from '@angular/router';
import { AuthService } from '../auth/auth.service';

@Component({
  selector: 'app-login',
  imports: [ReactiveFormsModule],
  templateUrl: './login.html',
  styleUrl: './login.scss'
})
export class Login {
  
  private authService = inject(AuthService);

  userForm = new FormGroup({
    email: new FormControl(''),
    password: new FormControl('')
  });

  onSubmit(){
    this.authService.login({
      username: this.userForm.value.email as string,
      password: this.userForm.value.password as string
    }).subscribe({
      next: () => {

      }
    })

  }
}
