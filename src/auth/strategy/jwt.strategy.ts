import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { DatabaseService } from 'src/database/database.service';


@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(config : ConfigService, private database : DatabaseService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      // TODO Change This Value To False In Production
      ignoreExpiration: true,
      secretOrKey: config.get('JWT_SECRET'),
    });
  }

  async validate(payload: { sub: number, email: string }) {
    const user = await this.database.user.findUnique({
        where: {
            id: payload.sub
        }
    });

    delete user.password;

    return user;
  }
}