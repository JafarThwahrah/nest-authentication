import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, 'local') {
  // local here is optional , and the default name for the strategy is local ,I just put it here to clearify from where did we bribg local inside the AuthGuard('local') in local-auth.guard.ts , if we removed it it will work
  constructor(private readonly authService: AuthService) {
    super({
      usernameField: 'email',
    });
  }

  async validate(email: string, password: string) {
    return await this.authService.verifyUser(email, password);
  }
}
